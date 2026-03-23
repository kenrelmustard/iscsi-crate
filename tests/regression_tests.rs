//! Regression tests for multi-PDU write, R2T flow, and Data-Out handling.
//!
//! These tests are self-contained — each starts an in-process iSCSI target,
//! connects with IscsiClient, and exercises the protocol paths that broke
//! in production with the TS-412 thin client boot.

use iscsi_target::pdu::opcode;
use iscsi_target::{IscsiClient, IscsiTarget, ScsiBlockDevice, ScsiResult, IscsiError};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

const TARGET_IQN: &str = "iqn.2025-12.local:storage.regtest";
const INITIATOR_IQN: &str = "iqn.2025-12.local:initiator.regtest";

// ---------------------------------------------------------------------------
// Test storage
// ---------------------------------------------------------------------------

struct TestStorage {
    data: Vec<u8>,
}

impl TestStorage {
    fn new(size_mb: usize) -> Self {
        TestStorage { data: vec![0u8; size_mb * 1024 * 1024] }
    }
}

impl ScsiBlockDevice for TestStorage {
    fn read(&self, lba: u64, blocks: u32, block_size: u32) -> ScsiResult<Vec<u8>> {
        let offset = (lba * block_size as u64) as usize;
        let len = (blocks * block_size) as usize;
        if offset + len > self.data.len() {
            return Err(IscsiError::Scsi("Read beyond capacity".into()));
        }
        Ok(self.data[offset..offset + len].to_vec())
    }

    fn write(&mut self, lba: u64, data: &[u8], block_size: u32) -> ScsiResult<()> {
        let offset = (lba * block_size as u64) as usize;
        if offset + data.len() > self.data.len() {
            return Err(IscsiError::Scsi("Write beyond capacity".into()));
        }
        self.data[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    fn capacity(&self) -> u64 {
        (self.data.len() / 512) as u64
    }

    fn block_size(&self) -> u32 {
        512
    }
}

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

fn find_free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start_target(size_mb: usize) -> (u16, Arc<IscsiTarget<TestStorage>>) {
    let _ = env_logger::try_init();
    let port = find_free_port();
    let storage = TestStorage::new(size_mb);
    let target = Arc::new(
        IscsiTarget::builder()
            .bind_addr(&format!("127.0.0.1:{}", port))
            .target_name(TARGET_IQN)
            .build(storage)
            .unwrap(),
    );
    let t = target.clone();
    std::thread::spawn(move || {
        let _ = t.run();
    });
    // Give the target time to bind and listen.
    // Don't probe with a TCP connection — handle_connection sets the global
    // running flag to false on exit, which would shut down the target.
    std::thread::sleep(Duration::from_millis(200));
    (port, target)
}

fn connect(port: u16) -> IscsiClient {
    let mut client = IscsiClient::connect(&format!("127.0.0.1:{}", port)).unwrap();
    client.login(INITIATOR_IQN, TARGET_IQN).unwrap();
    client
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Sanity: login, read one block, logout.
/// Exercises the fixed send_scsi_command byte layout and digest negotiation path.
#[test]
fn test_login_and_read() {
    let (port, target) = start_target(1);
    let mut client = connect(port);

    let (resp, data) = client.send_read(0, 1).unwrap();
    // Target piggybacks status on final Data-In (S-bit), or sends separate SCSI Response
    assert!(
        resp.opcode == opcode::SCSI_RESPONSE || resp.opcode == opcode::SCSI_DATA_IN,
        "Unexpected opcode 0x{:02x}", resp.opcode
    );
    assert_eq!(data.len(), 512);

    client.logout().unwrap();
    target.stop();
}

/// Write one block (fits in single PDU), read back and verify.
#[test]
fn test_single_pdu_write_integrity() {
    let (port, target) = start_target(1);
    let mut client = connect(port);

    let pattern: Vec<u8> = (0..512).map(|i| (i % 251) as u8).collect();
    let resp = client.send_write(0, &pattern).unwrap();
    assert_eq!(resp.opcode, opcode::SCSI_RESPONSE);

    let (_, read_data) = client.send_read(0, 1).unwrap();
    assert_eq!(read_data, pattern, "Single-block write/read mismatch");

    target.stop();
}

/// Write 32KB (< FirstBurstLength of 65536).
/// This sends immediate data + unsolicited Data-Out PDUs, no R2T needed.
/// Regression for bug 3: premature R2T when F=0.
#[test]
fn test_unsolicited_burst_only() {
    let (port, target) = start_target(1);
    let mut client = connect(port);

    let data: Vec<u8> = (0..32768).map(|i| ((i * 3) % 256) as u8).collect();
    let resp = client.send_write(0, &data).unwrap();
    assert_eq!(resp.opcode, opcode::SCSI_RESPONSE);

    let (_, read_data) = client.send_read(0, 64).unwrap();
    assert_eq!(read_data, data, "Unsolicited burst write/read mismatch");

    target.stop();
}

/// Write 128KB (> FirstBurstLength of 65536, < MaxBurstLength of 262144).
/// Forces one R2T round after the unsolicited burst.
/// Regression for bugs 2 (R2T overlap), 3 (F-bit), 4 (bytes_received).
#[test]
fn test_multi_pdu_write_with_r2t() {
    let (port, target) = start_target(1);
    let mut client = connect(port);

    let data: Vec<u8> = (0..131072).map(|i| ((i * 7) % 256) as u8).collect();
    let resp = client.send_write(0, &data).unwrap();
    assert_eq!(resp.opcode, opcode::SCSI_RESPONSE);

    let (_, read_data) = client.send_read(0, 256).unwrap();
    assert_eq!(read_data, data, "Multi-PDU R2T write/read mismatch");

    target.stop();
}

/// Write 384KB (> FirstBurstLength + MaxBurstLength), forcing multiple R2T rounds.
/// Regression for bug 2 (R2T overlap) and bug 4 (bytes_received overcounting).
#[test]
fn test_multiple_r2t_rounds() {
    let (port, target) = start_target(1);
    let mut client = connect(port);

    let data: Vec<u8> = (0..393216).map(|i| ((i * 13) % 256) as u8).collect();
    let resp = client.send_write(0, &data).unwrap();
    assert_eq!(resp.opcode, opcode::SCSI_RESPONSE);

    let (_, read_data) = client.send_read(0, 768).unwrap();
    assert_eq!(read_data, data, "Multi-R2T-round write/read mismatch");

    target.stop();
}

/// Verify CRC32C digest negotiation works end-to-end.
/// The client offers "CRC32C,None", the target should accept CRC32C,
/// and all subsequent PDUs should carry and verify CRC32C digests.
#[test]
fn test_crc32c_digest_negotiation() {
    let (port, target) = start_target(1);
    let mut client = connect(port);

    // If CRC32C negotiation is broken, commands will fail with digest mismatch.
    // Write + read with digests active.
    let pattern: Vec<u8> = (0..4096).map(|i| ((i * 41) % 256) as u8).collect();
    let resp = client.send_write(0, &pattern).unwrap();
    assert_eq!(resp.opcode, opcode::SCSI_RESPONSE);

    let (_, read_data) = client.send_read(0, 8).unwrap();
    assert_eq!(read_data, pattern, "CRC32C write/read integrity mismatch");

    client.logout().unwrap();
    target.stop();
}

/// Write a prime-number-offset pattern across multiple R2T rounds, then
/// read back and verify every byte. Catches any offset, length, or
/// buffer-copy bugs in the Data-Out path.
#[test]
fn test_write_read_data_integrity() {
    let (port, target) = start_target(1);
    let mut client = connect(port);

    // 200 blocks = 102400 bytes — crosses FirstBurstLength boundary
    let mut pattern = vec![0u8; 102400];
    for (i, b) in pattern.iter_mut().enumerate() {
        *b = ((i.wrapping_mul(251).wrapping_add(17)) % 256) as u8;
    }

    let resp = client.send_write(100, &pattern).unwrap();
    assert_eq!(resp.opcode, opcode::SCSI_RESPONSE);

    let (_, read_data) = client.send_read(100, 200).unwrap();
    assert_eq!(read_data.len(), pattern.len());
    for (i, (&expected, &actual)) in pattern.iter().zip(read_data.iter()).enumerate() {
        assert_eq!(expected, actual, "Mismatch at byte offset {}", i);
    }

    target.stop();
}
