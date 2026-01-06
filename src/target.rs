//! iSCSI target server implementation
//!
//! This module provides the main server structure, TCP listener, and connection handling.

use crate::error::{IscsiError, ScsiResult};
use crate::pdu::{self, IscsiPdu, BHS_SIZE, opcode, flags, scsi_status, serialize_text_parameters};
use crate::scsi::{ScsiBlockDevice, ScsiHandler, ScsiResponse};
use crate::typestate_session::{AnySession, SessionData};
use crate::session::PendingWrite;
use crate::pdu::ScsiCommandPdu;
use byteorder::{BigEndian, ByteOrder};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, Shutdown};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::Duration;

/// Default iSCSI port
pub const ISCSI_PORT: u16 = 3260;

/// iSCSI target server
pub struct IscsiTarget<D: ScsiBlockDevice> {
    bind_addr: String,
    target_name: String,
    target_alias: String,
    device: Arc<Mutex<D>>,
    running: Arc<AtomicBool>,
    shutting_down: Arc<AtomicBool>,
    auth_config: crate::auth::AuthConfig,
    max_connections: u32,
    active_connections: Arc<std::sync::atomic::AtomicUsize>,
    max_sessions: u32,
    active_sessions: Arc<std::sync::atomic::AtomicUsize>,
    allowed_initiators: Option<Vec<String>>,
}

impl<D: ScsiBlockDevice + Send + 'static> IscsiTarget<D> {
    /// Create a new builder for configuring the target
    pub fn builder() -> IscsiTargetBuilder<D> {
        IscsiTargetBuilder::new()
    }

    /// Run the iSCSI target server
    ///
    /// This blocks the current thread and processes incoming connections.
    pub fn run(&self) -> ScsiResult<()> {
        log::info!("iSCSI target starting on {}", self.bind_addr);
        log::info!("Target name: {}", self.target_name);

        let listener = TcpListener::bind(&self.bind_addr)
            .map_err(IscsiError::Io)?;

        // Set non-blocking for graceful shutdown checking
        listener.set_nonblocking(true)
            .map_err(IscsiError::Io)?;

        self.running.store(true, Ordering::SeqCst);

        log::info!("iSCSI target listening on {}", self.bind_addr);

        while self.running.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, addr)) => {
                    log::info!("New connection from {}", addr);

                    // Check connection limit
                    let current = self.active_connections.fetch_add(1, Ordering::SeqCst);
                    if current >= self.max_connections as usize {
                        log::warn!("Connection rejected from {}: too many connections ({}/{})",
                            addr, current + 1, self.max_connections);
                        self.active_connections.fetch_sub(1, Ordering::SeqCst);

                        // Send TOO_MANY_CONNECTIONS reject and close
                        let _ = send_connection_limit_reject(stream);
                        continue;
                    }

                    log::debug!("Accepted connection from {} ({}/{} active)",
                        addr, current + 1, self.max_connections);

                    let device = Arc::clone(&self.device);
                    let target_name = self.target_name.clone();
                    let target_alias = self.target_alias.clone();
                    let auth_config = self.auth_config.clone();
                    let running = Arc::clone(&self.running);
                    let shutting_down = Arc::clone(&self.shutting_down);
                    let active_connections = Arc::clone(&self.active_connections);
                    let max_sessions = self.max_sessions;
                    let active_sessions = Arc::clone(&self.active_sessions);
                    let allowed_initiators = self.allowed_initiators.clone();

                    thread::spawn(move || {
                        let session_entered = handle_connection(
                            stream,
                            device,
                            &target_name,
                            &target_alias,
                            auth_config,
                            running,
                            shutting_down,
                            max_sessions,
                            Arc::clone(&active_sessions),
                            allowed_initiators,
                        ).unwrap_or(false); // Returns true if session was established

                        log::info!("Connection closed from {}", addr);

                        // Decrement connection count
                        let prev = active_connections.fetch_sub(1, Ordering::SeqCst);
                        log::debug!("Connection count: {} -> {}", prev, prev - 1);

                        // Decrement session count if a session was established
                        if session_entered {
                            let prev = active_sessions.fetch_sub(1, Ordering::SeqCst);
                            log::debug!("Session count: {} -> {}", prev, prev - 1);
                        }
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No connection available, sleep briefly and retry
                    thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    log::error!("Accept error: {}", e);
                }
            }
        }

        log::info!("iSCSI target shutting down");
        Ok(())
    }

    /// Get the current number of active connections
    pub fn active_connection_count(&self) -> usize {
        self.active_connections.load(Ordering::SeqCst)
    }

    /// Get the current number of active sessions
    pub fn active_session_count(&self) -> usize {
        self.active_sessions.load(Ordering::SeqCst)
    }

    /// Initiate graceful shutdown - reject new logins but allow existing sessions to complete
    pub fn shutdown_gracefully(&self) {
        log::info!("Initiating graceful shutdown - new logins will be rejected");
        self.shutting_down.store(true, Ordering::SeqCst);
    }

    /// Signal the server to stop immediately
    pub fn stop(&self) {
        log::info!("Stopping iSCSI target server");
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if the server is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Check if the server is in graceful shutdown mode
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }
}

/// Send TOO_MANY_CONNECTIONS reject to a new connection
fn send_connection_limit_reject(mut stream: TcpStream) -> ScsiResult<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(2))).ok();

    let mut bhs = [0u8; 48];
    if stream.read_exact(&mut bhs).is_ok() {
        let itt = u32::from_be_bytes([bhs[16], bhs[17], bhs[18], bhs[19]]);
        let data = SessionData::default();
        let reject_pdu = data.create_login_reject(itt, pdu::login_status::INITIATOR_ERROR, 0x06);
        let _ = write_pdu(&mut stream, &reject_pdu);
    }

    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

/// Handle a single iSCSI connection using typestate session
fn handle_connection<D: ScsiBlockDevice>(
    mut stream: TcpStream,
    device: Arc<Mutex<D>>,
    target_name: &str,
    target_alias: &str,
    auth_config: crate::auth::AuthConfig,
    running: Arc<AtomicBool>,
    shutting_down: Arc<AtomicBool>,
    max_sessions: u32,
    active_sessions: Arc<std::sync::atomic::AtomicUsize>,
    allowed_initiators: Option<Vec<String>>,
) -> ScsiResult<bool> {
    let local_addr = stream.local_addr().map_err(IscsiError::Io)?;
    stream.set_nonblocking(false).map_err(IscsiError::Io)?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(IscsiError::Io)?;
    stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(IscsiError::Io)?;

    // Create session using typestate pattern with AnySession wrapper
    let mut session = AnySession::new_configured(
        auth_config,
        target_name,
        target_alias,
        allowed_initiators,
    );

    let mut session_entered = false;

    // Fix bind address 0.0.0.0 -> actual reachable address
    let target_address = if local_addr.ip().is_unspecified() {
        // If bound to 0.0.0.0, use localhost for discovery
        // TODO: Use actual server IP or make this configurable
        format!("127.0.0.1:{}", local_addr.port())
    } else {
        local_addr.to_string()
    };

    // Main connection loop
    while running.load(Ordering::SeqCst) {
        let pdu = match read_pdu(&mut stream) {
            Ok(pdu) => pdu,
            Err(IscsiError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                log::debug!("Connection closed by initiator");
                break;
            }
            Err(IscsiError::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(IscsiError::Io(ref e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                log::debug!("Connection timeout, closing");
                break;
            }
            Err(e) => {
                log::error!("Error reading PDU: {}", e);
                break;
            }
        };

        log::debug!("Received PDU: {} (opcode 0x{:02x}) in state {}",
            pdu.opcode_name(), pdu.opcode, session.state_name());

        let was_full_feature = session.is_full_feature();

        // Process PDU based on session state
        let responses = if session.is_login_phase() {
            handle_login_phase(&mut session, &pdu, target_name, &target_address, &shutting_down, max_sessions, &active_sessions)?
        } else if session.is_full_feature() {
            handle_full_feature_phase(&mut session, &pdu, &device, target_name, &target_address)?
        } else {
            // Session ended (Logout or Failed)
            log::info!("Session ended (state: {})", session.state_name());
            break;
        };

        // Detect transition to FullFeaturePhase
        if !was_full_feature && session.is_full_feature() {
            log::info!("Session entered FullFeaturePhase, increasing timeout");
            stream.set_read_timeout(Some(Duration::from_secs(300))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(30))).ok();

            session_entered = true;
            let count = active_sessions.fetch_add(1, Ordering::SeqCst);
            log::debug!("Session count: {} -> {}", count, count + 1);
        }

        // Send responses
        for resp_pdu in responses {
            log::debug!("Sending PDU: {} (opcode 0x{:02x})", resp_pdu.opcode_name(), resp_pdu.opcode);
            write_pdu(&mut stream, &resp_pdu)?;
        }

        // Check if session ended
        if session.is_ended() {
            log::info!("Session ending (state: {})", session.state_name());
            break;
        }
    }

    let _ = stream.shutdown(Shutdown::Both);
    Ok(session_entered)
}

/// Read a PDU from the TCP stream
fn read_pdu(stream: &mut TcpStream) -> ScsiResult<IscsiPdu> {
    let mut bhs = [0u8; BHS_SIZE];
    stream.read_exact(&mut bhs).map_err(IscsiError::Io)?;

    let ahs_length = bhs[4] as usize * 4;
    let data_length = ((bhs[5] as u32) << 16) | ((bhs[6] as u32) << 8) | (bhs[7] as u32);
    let padded_data_len = (data_length as usize).div_ceil(4) * 4;

    let total_len = BHS_SIZE + ahs_length + padded_data_len;
    let mut full_pdu = vec![0u8; total_len];
    full_pdu[..BHS_SIZE].copy_from_slice(&bhs);

    if total_len > BHS_SIZE {
        stream.read_exact(&mut full_pdu[BHS_SIZE..]).map_err(IscsiError::Io)?;
    }

    let pdu = IscsiPdu::from_bytes(&full_pdu)?;

    if full_pdu.len() >= 48 {
        log::debug!("Received PDU header hex: {}", full_pdu[0..48].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
    }

    Ok(pdu)
}

/// Write a PDU to the TCP stream
fn write_pdu(stream: &mut TcpStream, pdu: &IscsiPdu) -> ScsiResult<()> {
    let bytes = pdu.to_bytes();

    if bytes.len() >= 48 {
        log::debug!("Sending PDU header hex: {}", bytes[0..48].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
    }

    stream.write_all(&bytes).map_err(IscsiError::Io)?;
    stream.flush().map_err(IscsiError::Io)?;
    Ok(())
}

/// Handle PDUs during login phase (using typestate session)
fn handle_login_phase(
    session: &mut AnySession,
    pdu: &IscsiPdu,
    target_name: &str,
    target_address: &str,
    shutting_down: &Arc<AtomicBool>,
    max_sessions: u32,
    active_sessions: &Arc<std::sync::atomic::AtomicUsize>,
) -> ScsiResult<Vec<IscsiPdu>> {
    match pdu.opcode {
        opcode::LOGIN_REQUEST => {
            // Check shutdown and session limits for new logins
            if let Some(data) = session.data() {
                if shutting_down.load(Ordering::SeqCst) && data.isid == [0u8; 6] {
                    log::warn!("Login rejected: target is shutting down");
                    let response = data.create_shutdown_reject(pdu.itt);
                    return Ok(vec![response]);
                }

                if data.isid == [0u8; 6] {
                    let current_sessions = active_sessions.load(Ordering::SeqCst);
                    if current_sessions >= max_sessions as usize {
                        log::warn!("Login rejected: session limit reached ({}/{})", current_sessions, max_sessions);
                        let response = data.create_out_of_resources_reject(pdu.itt);
                        return Ok(vec![response]);
                    }
                }
            }

            // Process login using typestate session
            // We need to take ownership and replace session
            let old_session = std::mem::replace(session, AnySession::new());
            let (new_session, responses) = old_session.process_login(pdu, target_name)?;
            *session = new_session;

            Ok(responses)
        }
        opcode::TEXT_REQUEST => {
            handle_text_request(session, pdu, target_name, target_address)
        }
        _ => {
            log::warn!("Invalid opcode 0x{:02x} during login phase", pdu.opcode);
            if let Some(data) = session.data() {
                let response = data.create_invalid_request_during_login_reject(pdu.itt);
                Ok(vec![response])
            } else {
                Ok(vec![])
            }
        }
    }
}

/// Handle PDUs during full feature phase
fn handle_full_feature_phase<D: ScsiBlockDevice>(
    session: &mut AnySession,
    pdu: &IscsiPdu,
    device: &Arc<Mutex<D>>,
    target_name: &str,
    target_address: &str,
) -> ScsiResult<Vec<IscsiPdu>> {
    match pdu.opcode {
        opcode::SCSI_COMMAND => {
            handle_scsi_command(session, pdu, device)
        }
        opcode::SCSI_DATA_OUT => {
            handle_scsi_data_out(session, pdu, device)
        }
        opcode::NOP_OUT => {
            let response = session.process_nop_out(pdu)?;
            Ok(vec![response])
        }
        opcode::LOGOUT_REQUEST => {
            // Process logout - this transitions session state
            let old_session = std::mem::replace(session, AnySession::new());
            let (new_session, response) = old_session.process_logout(pdu)?;
            *session = new_session;
            Ok(vec![response])
        }
        opcode::TEXT_REQUEST => {
            handle_text_request(session, pdu, target_name, target_address)
        }
        opcode::TASK_MANAGEMENT_REQUEST => {
            handle_task_management(session, pdu)
        }
        _ => {
            log::warn!("Unsupported opcode 0x{:02x} in full feature phase", pdu.opcode);
            Ok(vec![])
        }
    }
}

/// Handle SCSI Command PDU
fn handle_scsi_command<D: ScsiBlockDevice>(
    session: &mut AnySession,
    pdu: &IscsiPdu,
    device: &Arc<Mutex<D>>,
) -> ScsiResult<Vec<IscsiPdu>> {
    let cmd = pdu.parse_scsi_command()?;
    let data = session.data_mut().ok_or_else(|| IscsiError::Protocol("Session not in FullFeaturePhase".to_string()))?;

    log::warn!(
        "SCSI Command: CDB[0]=0x{:02x}, LUN=0x{:016x}, ITT=0x{:08x}, ExpLen={}, read={}, write={}, final={}, data_len={}",
        cmd.cdb[0], cmd.lun, cmd.itt, cmd.expected_data_length, cmd.read, cmd.write, cmd.final_flag, pdu.data.len()
    );

    // Validate LUN
    if cmd.lun != 0 {
        log::warn!("Command 0x{:02x} to invalid LUN: 0x{:016x}", cmd.cdb[0], cmd.lun);
        let sense = crate::scsi::SenseData::new(
            crate::scsi::sense_key::ILLEGAL_REQUEST,
            crate::scsi::asc::LOGICAL_UNIT_NOT_SUPPORTED,
            0,
        );
        return Ok(vec![IscsiPdu::scsi_response(
            cmd.itt, data.next_stat_sn(), data.exp_cmd_sn, data.max_cmd_sn,
            pdu::scsi_status::CHECK_CONDITION, 0, 0, Some(&sense.to_bytes()),
        )]);
    }

    // Validate CmdSN
    let cmd_sn = BigEndian::read_u32(&pdu.specific[4..8]);
    if !data.validate_cmd_sn(cmd_sn) {
        log::warn!("Invalid CmdSN: {}, expected: {}", cmd_sn, data.exp_cmd_sn);
    }

    let opcode = cmd.cdb[0];
    let is_sync_cache = opcode == 0x35 || opcode == 0x91;
    let is_write_cmd = matches!(opcode, 0x0a | 0x2a | 0x8a);

    // Handle WRITE commands
    if is_write_cmd {
        return handle_write_command(data, pdu, &cmd, device);
    }

    // Handle non-write commands
    let response = if opcode == 0x03 {
        // REQUEST SENSE
        log::info!("REQUEST SENSE called");
        if cmd.cdb.len() < 6 {
            ScsiResponse::check_condition(crate::scsi::SenseData::invalid_command())
        } else {
            let alloc_len = cmd.cdb[4] as usize;
            let mut sense_data = match &data.last_sense_data {
                Some(bytes) => bytes.clone(),
                None => crate::scsi::SenseData::new(
                    crate::scsi::sense_key::NO_SENSE,
                    crate::scsi::asc::NO_ADDITIONAL_SENSE,
                    0,
                ).to_bytes(),
            };
            sense_data.truncate(alloc_len.min(sense_data.len()));
            ScsiResponse::good(sense_data)
        }
    } else if is_sync_cache {
        let mut device_guard = device.lock().map_err(|_| IscsiError::Scsi("Device lock poisoned".to_string()))?;
        device_guard.flush()?;
        ScsiResponse::good_no_data()
    } else {
        let device_guard = device.lock().map_err(|_| IscsiError::Scsi("Device lock poisoned".to_string()))?;
        ScsiHandler::handle_command(&cmd.cdb, &*device_guard, None)?
    };

    // Build response PDU(s)
    build_scsi_response(data, &cmd, response)
}

fn handle_write_command<D: ScsiBlockDevice>(
    data: &mut SessionData,
    pdu: &IscsiPdu,
    cmd: &ScsiCommandPdu,
    device: &Arc<Mutex<D>>,
) -> ScsiResult<Vec<IscsiPdu>> {
    let opcode = cmd.cdb[0];

    let (lba, transfer_length) = match opcode {
        0x0a | 0x2a => {
            if opcode == 0x0a && cmd.cdb.len() >= 6 {
                let lba_21 = ((cmd.cdb[1] as u32 & 0x1F) << 16)
                           | ((cmd.cdb[2] as u32) << 8)
                           | (cmd.cdb[3] as u32);
                (lba_21 as u64, cmd.cdb[4] as u32)
            } else if opcode == 0x2a && cmd.cdb.len() >= 10 {
                let lba = BigEndian::read_u32(&cmd.cdb[2..6]) as u64;
                let length = BigEndian::read_u16(&cmd.cdb[7..9]) as u32;
                (lba, length)
            } else {
                (0, 0)
            }
        }
        0x8a => {
            if cmd.cdb.len() >= 16 {
                let lba = BigEndian::read_u64(&cmd.cdb[2..10]);
                let length = BigEndian::read_u32(&cmd.cdb[10..14]);
                (lba, length)
            } else {
                (0, 0)
            }
        }
        _ => (0, 0),
    };

    if transfer_length > 0 {
        let device_guard = device.lock().map_err(|_| IscsiError::Scsi("Device lock poisoned".to_string()))?;
        let block_size = device_guard.block_size();
        drop(device_guard);

        let expected_data_len = transfer_length as usize * block_size as usize;
        let bytes_received = pdu.data.len() as u32;

        // Check if this is a single-PDU write (all data fits in immediate data)
        if bytes_received as usize == expected_data_len {
            // Single-PDU write - write directly
            let mut device_guard = device.lock().map_err(|_| IscsiError::Scsi("Device lock poisoned".to_string()))?;
            if let Err(e) = device_guard.write(lba, &pdu.data, block_size) {
                log::error!("Write failed: {}", e);
                let sense = crate::scsi::SenseData::medium_error();
                return Ok(vec![IscsiPdu::scsi_response(
                    cmd.itt, data.next_stat_sn(), data.exp_cmd_sn, data.max_cmd_sn,
                    pdu::scsi_status::CHECK_CONDITION, 0, 0, Some(&sense.to_bytes()),
                )]);
            }
            return Ok(vec![IscsiPdu::scsi_response(
                cmd.itt, data.next_stat_sn(), data.exp_cmd_sn, data.max_cmd_sn,
                pdu::scsi_status::GOOD, 0, 0, None,
            )]);
        }

        // Multi-PDU write - create buffer and copy immediate data
        let mut buffer = vec![0u8; expected_data_len];
        if !pdu.data.is_empty() {
            buffer[..pdu.data.len()].copy_from_slice(&pdu.data);
        }

        let ttt = data.next_target_transfer_tag();
        data.pending_writes.insert(cmd.itt, PendingWrite {
            lba, transfer_length, block_size, bytes_received, ttt, r2t_sn: 0, lun: cmd.lun,
            buffer,
        });

        // Send R2T to request remaining data
        let max_burst = data.params.max_burst_length;
        let mut responses = Vec::new();
        let mut offset = bytes_received;
        let mut r2t_sn = 0u32;

        while offset < expected_data_len as u32 {
            let remaining = expected_data_len as u32 - offset;
            let request_len = remaining.min(max_burst);

            responses.push(IscsiPdu::r2t(
                cmd.lun, cmd.itt, ttt, data.stat_sn,
                data.exp_cmd_sn, data.max_cmd_sn,
                r2t_sn, offset, request_len,
            ));

            offset += request_len;
            r2t_sn += 1;
        }

        if let Some(pending) = data.pending_writes.get_mut(&cmd.itt) {
            pending.r2t_sn = r2t_sn;
        }

        return Ok(responses);
    }

    Ok(vec![IscsiPdu::scsi_response(
        cmd.itt, data.next_stat_sn(), data.exp_cmd_sn, data.max_cmd_sn,
        pdu::scsi_status::GOOD, 0, 0, None,
    )])
}

fn build_scsi_response(
    data: &mut SessionData,
    cmd: &ScsiCommandPdu,
    response: ScsiResponse,
) -> ScsiResult<Vec<IscsiPdu>> {
    let mut responses = Vec::new();

    if cmd.read && !response.data.is_empty() {
        let max_data_seg = data.params.max_xmit_data_segment_length as usize;
        let mut offset = 0u32;
        let mut data_sn = 0u32;

        while offset < response.data.len() as u32 {
            let remaining = response.data.len() - offset as usize;
            let chunk_size = remaining.min(max_data_seg);
            let is_final = offset as usize + chunk_size >= response.data.len();

            let chunk = response.data[offset as usize..offset as usize + chunk_size].to_vec();
            let pdu_stat_sn = if is_final { data.next_stat_sn() } else { 0 };

            let data_in = IscsiPdu::scsi_data_in(
                cmd.itt, 0xFFFF_FFFF, pdu_stat_sn,
                data.exp_cmd_sn, data.max_cmd_sn,
                data_sn, offset, chunk, is_final,
                if is_final { Some(response.status) } else { None },
            );

            responses.push(data_in);
            offset += chunk_size as u32;
            data_sn += 1;
        }
    } else {
        let sense_data = response.sense.as_ref().map(|s| s.to_bytes());

        if response.status == pdu::scsi_status::CHECK_CONDITION {
            if let Some(ref sd) = response.sense {
                let sense_bytes = sd.to_bytes();
                log::info!("CHECK CONDITION: sense_key=0x{:02x}, asc=0x{:02x}", sd.sense_key, sd.asc);
                data.last_sense_data = Some(sense_bytes);
            }
        } else {
            data.last_sense_data = None;
        }

        let scsi_resp = IscsiPdu::scsi_response(
            cmd.itt, data.next_stat_sn(), data.exp_cmd_sn, data.max_cmd_sn,
            response.status, 0, 0, sense_data.as_deref(),
        );
        responses.push(scsi_resp);
    }

    Ok(responses)
}

/// Handle SCSI Data-Out PDU
fn handle_scsi_data_out<D: ScsiBlockDevice>(
    session: &mut AnySession,
    pdu: &IscsiPdu,
    device: &Arc<Mutex<D>>,
) -> ScsiResult<Vec<IscsiPdu>> {
    let data_out = pdu.parse_scsi_data_out()?;
    let data = session.data_mut().ok_or_else(|| IscsiError::Protocol("Session not in FullFeaturePhase".to_string()))?;

    let pending = data.pending_writes.get_mut(&data_out.itt);
    if pending.is_none() {
        log::warn!("Received Data-Out for unknown ITT=0x{:08x}", data_out.itt);
        return Ok(vec![]);
    }

    let pending = pending.unwrap();
    let block_size = pending.block_size;
    let transfer_length = pending.transfer_length;
    let lba = pending.lba;
    let total_expected = transfer_length * block_size;

    // Copy data into buffer at the correct offset
    let start_offset = data_out.buffer_offset as usize;
    let end_offset = start_offset + data_out.data.len();

    if end_offset > pending.buffer.len() {
        log::error!("DATA-OUT offset {} + len {} exceeds buffer size {}",
            data_out.buffer_offset, data_out.data.len(), pending.buffer.len());
        let sense = crate::scsi::SenseData::medium_error();
        return Ok(vec![IscsiPdu::scsi_response(
            data_out.itt, data.next_stat_sn(), data.exp_cmd_sn, data.max_cmd_sn,
            pdu::scsi_status::CHECK_CONDITION, 0, 0, Some(&sense.to_bytes()),
        )]);
    }

    pending.buffer[start_offset..end_offset].copy_from_slice(&data_out.data);

    if end_offset as u32 > pending.bytes_received {
        pending.bytes_received = end_offset as u32;
    }

    // Check if transfer is complete
    if pending.bytes_received >= total_expected {
        let itt = data_out.itt;
        let buffer = pending.buffer.clone();
        data.pending_writes.remove(&itt);

        // Now write the complete buffer to the device in one operation
        let mut device_guard = device.lock().map_err(|_| IscsiError::Scsi("Device lock poisoned".to_string()))?;
        let write_result = device_guard.write(lba, &buffer, block_size);
        drop(device_guard);

        let (status, sense) = match write_result {
            Ok(()) => (scsi_status::GOOD, None),
            Err(e) => {
                log::error!("Write failed: {}", e);
                (pdu::scsi_status::CHECK_CONDITION, Some(crate::scsi::SenseData::medium_error().to_bytes()))
            }
        };

        return Ok(vec![IscsiPdu::scsi_response(
            itt, data.next_stat_sn(), data.exp_cmd_sn, data.max_cmd_sn,
            status, 0, 0, sense.as_deref(),
        )]);
    }

    // Transfer not complete yet, no response needed
    Ok(vec![])
}

/// Handle Text Request
fn handle_text_request(
    session: &mut AnySession,
    pdu: &IscsiPdu,
    target_name: &str,
    target_address: &str,
) -> ScsiResult<Vec<IscsiPdu>> {
    let text_req = pdu.parse_text_request()?;

    let is_send_targets = text_req.parameters.iter()
        .any(|(k, v)| k == "SendTargets" && (v == "All" || v.is_empty()));

    let response_params = if is_send_targets {
        vec![
            ("TargetName".to_string(), target_name.to_string()),
            ("TargetAddress".to_string(), format!("{},1", target_address)),
        ]
    } else {
        vec![]
    };

    let response_data = serialize_text_parameters(&response_params);

    let data = session.data_mut().ok_or_else(|| IscsiError::Protocol("No session data".to_string()))?;

    let response = IscsiPdu::text_response(
        text_req.itt, 0xFFFF_FFFF,
        data.next_stat_sn(), data.exp_cmd_sn, data.max_cmd_sn,
        true, response_data,
    );

    Ok(vec![response])
}

/// Handle Task Management Request
fn handle_task_management(
    session: &mut AnySession,
    pdu: &IscsiPdu,
) -> ScsiResult<Vec<IscsiPdu>> {
    let function = pdu.flags & 0x7F;
    log::debug!("Task Management: function={}", function);

    let data = session.data_mut().ok_or_else(|| IscsiError::Protocol("No session data".to_string()))?;

    let mut response = IscsiPdu::new();
    response.opcode = opcode::TASK_MANAGEMENT_RESPONSE;
    response.flags = flags::FINAL;
    response.itt = pdu.itt;

    response.specific[0] = 0x00; // function complete
    response.specific[4..8].copy_from_slice(&data.next_stat_sn().to_be_bytes());
    response.specific[8..12].copy_from_slice(&data.exp_cmd_sn.to_be_bytes());
    response.specific[12..16].copy_from_slice(&data.max_cmd_sn.to_be_bytes());

    Ok(vec![response])
}

/// Builder for configuring an iSCSI target
pub struct IscsiTargetBuilder<D: ScsiBlockDevice> {
    bind_addr: Option<String>,
    target_name: Option<String>,
    target_alias: Option<String>,
    auth_config: crate::auth::AuthConfig,
    max_connections: Option<u32>,
    max_sessions: Option<u32>,
    allowed_initiators: Option<Vec<String>>,
    _phantom: std::marker::PhantomData<D>,
}

impl<D: ScsiBlockDevice> IscsiTargetBuilder<D> {
    fn new() -> Self {
        Self {
            bind_addr: None,
            target_name: None,
            target_alias: None,
            auth_config: crate::auth::AuthConfig::None,
            max_connections: None,
            max_sessions: None,
            allowed_initiators: None,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn bind_addr(mut self, addr: &str) -> Self {
        self.bind_addr = Some(addr.to_string());
        self
    }

    pub fn target_name(mut self, name: &str) -> Self {
        self.target_name = Some(name.to_string());
        self
    }

    pub fn target_alias(mut self, alias: &str) -> Self {
        self.target_alias = Some(alias.to_string());
        self
    }

    pub fn with_auth(mut self, auth_config: crate::auth::AuthConfig) -> Self {
        self.auth_config = auth_config;
        self
    }

    pub fn max_connections(mut self, max: u32) -> Self {
        self.max_connections = Some(max);
        self
    }

    pub fn max_sessions(mut self, max: u32) -> Self {
        self.max_sessions = Some(max);
        self
    }

    pub fn allowed_initiators(mut self, initiators: Vec<String>) -> Self {
        self.allowed_initiators = Some(initiators);
        self
    }

    pub fn build(self, device: D) -> ScsiResult<IscsiTarget<D>> {
        let bind_addr = self.bind_addr.unwrap_or_else(|| format!("0.0.0.0:{}", ISCSI_PORT));
        let target_name = self.target_name.unwrap_or_else(|| "iqn.2025-12.local:storage.default".to_string());
        let target_alias = self.target_alias.unwrap_or_else(|| "iSCSI Target".to_string());

        if !target_name.starts_with("iqn.") && !target_name.starts_with("eui.") && !target_name.starts_with("naa.") {
            return Err(IscsiError::Config(
                "target_name must be in IQN, EUI, or NAA format".to_string()
            ));
        }

        Ok(IscsiTarget {
            bind_addr,
            target_name,
            target_alias,
            device: Arc::new(Mutex::new(device)),
            running: Arc::new(AtomicBool::new(false)),
            shutting_down: Arc::new(AtomicBool::new(false)),
            auth_config: self.auth_config,
            max_connections: self.max_connections.unwrap_or(16),
            active_connections: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            max_sessions: self.max_sessions.unwrap_or(256),
            active_sessions: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            allowed_initiators: self.allowed_initiators,
        })
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDevice {
        capacity: u64,
        block_size: u32,
        data: Vec<u8>,
    }

    impl MockDevice {
        fn new(capacity: u64, block_size: u32) -> Self {
            let size = (capacity * block_size as u64) as usize;
            MockDevice { capacity, block_size, data: vec![0u8; size] }
        }
    }

    impl ScsiBlockDevice for MockDevice {
        fn read(&self, lba: u64, blocks: u32, block_size: u32) -> ScsiResult<Vec<u8>> {
            let offset = (lba * block_size as u64) as usize;
            let len = (blocks * block_size) as usize;
            if offset + len > self.data.len() {
                return Err(IscsiError::Scsi("Read out of bounds".into()));
            }
            Ok(self.data[offset..offset + len].to_vec())
        }

        fn write(&mut self, lba: u64, data: &[u8], block_size: u32) -> ScsiResult<()> {
            let offset = (lba * block_size as u64) as usize;
            if offset + data.len() > self.data.len() {
                return Err(IscsiError::Scsi("Write out of bounds".into()));
            }
            self.data[offset..offset + data.len()].copy_from_slice(data);
            Ok(())
        }

        fn capacity(&self) -> u64 { self.capacity }
        fn block_size(&self) -> u32 { self.block_size }
    }

    #[test]
    fn test_builder_default() {
        let device = MockDevice::new(1000, 512);
        let target = IscsiTarget::builder().build(device).unwrap();
        assert_eq!(target.bind_addr, "0.0.0.0:3260");
        assert!(target.target_name.starts_with("iqn."));
    }

    #[test]
    fn test_builder_custom() {
        let device = MockDevice::new(1000, 512);
        let target = IscsiTarget::builder()
            .bind_addr("127.0.0.1:3260")
            .target_name("iqn.2025-12.test:disk1")
            .target_alias("Test Disk")
            .build(device)
            .unwrap();

        assert_eq!(target.bind_addr, "127.0.0.1:3260");
        assert_eq!(target.target_name, "iqn.2025-12.test:disk1");
    }

    #[test]
    fn test_builder_invalid_iqn() {
        let device = MockDevice::new(1000, 512);
        let result = IscsiTarget::builder()
            .target_name("invalid-name")
            .build(device);
        assert!(result.is_err());
    }

    #[test]
    fn test_running_flag() {
        let device = MockDevice::new(1000, 512);
        let target = IscsiTarget::builder().build(device).unwrap();

        assert!(!target.is_running());
        target.running.store(true, Ordering::SeqCst);
        assert!(target.is_running());
        target.stop();
        assert!(!target.is_running());
    }
}
