//! Typestate-based iSCSI session management
//!
//! This module demonstrates how to use Rust's type system to enforce valid
//! state transitions at compile time. Invalid state transitions become
//! compile errors rather than runtime errors.
//!
//! ## Key Benefits
//! - **Compile-time safety**: Invalid operations don't compile
//! - **Self-documenting**: The API shows what's possible in each state
//! - **Zero runtime cost**: No state checks or match statements needed
//!
//! ## State Machine (RFC 3720 Section 5)
//! ```text
//! Free --> SecurityNegotiation --> LoginOperationalNegotiation --> FullFeaturePhase --> Logout
//!                    |                                                    |
//!                    +---------------> FullFeaturePhase -----------------+
//!                                           |
//!                                           v
//!                                        Failed
//! ```

use crate::auth::{AuthConfig, ChapAuthState};
use crate::error::{IscsiError, ScsiResult};
use crate::pdu::{self, IscsiPdu, LoginRequest, serialize_text_parameters};
use crate::session::{PendingWrite, SessionParams, SessionType};
use std::collections::HashMap;
use std::marker::PhantomData;

// =============================================================================
// State Types (Zero-sized types used as type parameters)
// =============================================================================

/// Session is in Free state - waiting for first login PDU
pub struct Free;

/// Session is in Security Negotiation phase (CHAP, etc.)
pub struct SecurityNegotiation;

/// Session is in Login Operational Negotiation phase
pub struct LoginOperationalNegotiation;

/// Session is in Full Feature Phase - ready for SCSI commands
pub struct FullFeaturePhase;

/// Session is in Logout state
pub struct Logout;

/// Session is in Failed state
pub struct Failed;

// =============================================================================
// Sealed trait to prevent external implementations
// =============================================================================

mod private {
    pub trait Sealed {}
    impl Sealed for super::Free {}
    impl Sealed for super::SecurityNegotiation {}
    impl Sealed for super::LoginOperationalNegotiation {}
    impl Sealed for super::FullFeaturePhase {}
    impl Sealed for super::Logout {}
    impl Sealed for super::Failed {}
}

/// Marker trait for valid session states
pub trait SessionState: private::Sealed {}
impl SessionState for Free {}
impl SessionState for SecurityNegotiation {}
impl SessionState for LoginOperationalNegotiation {}
impl SessionState for FullFeaturePhase {}
impl SessionState for Logout {}
impl SessionState for Failed {}

/// Marker trait for login-phase states (can process login PDUs)
pub trait LoginPhaseState: SessionState {}
impl LoginPhaseState for Free {}
impl LoginPhaseState for SecurityNegotiation {}
impl LoginPhaseState for LoginOperationalNegotiation {}

/// Marker trait for states that can transition to FullFeaturePhase
pub trait CanEnterFullFeature: SessionState {}
impl CanEnterFullFeature for SecurityNegotiation {}
impl CanEnterFullFeature for LoginOperationalNegotiation {}

// =============================================================================
// Core Session Data (shared across all states)
// =============================================================================

/// Core session data shared across all states
#[derive(Debug, Clone)]
pub struct SessionData {
    /// Initiator Session ID (6 bytes)
    pub isid: [u8; 6],
    /// Target Session Identifying Handle
    pub tsih: u16,
    /// Connection ID
    pub cid: u16,
    /// Session type
    pub session_type: SessionType,
    /// Negotiated parameters
    pub params: SessionParams,

    // Sequence numbers
    pub exp_cmd_sn: u32,
    pub max_cmd_sn: u32,
    pub stat_sn: u32,

    // Login tracking
    current_stage: u8,
    next_stage: u8,

    // Command tracking
    pub pending_writes: HashMap<u32, PendingWrite>,
    pub next_ttt: u32,
    pub last_sense_data: Option<Vec<u8>>,

    // Authentication
    pub auth_config: AuthConfig,
    pub chap_state: Option<ChapAuthState>,
    pub target_chap_state: Option<ChapAuthState>,
    pub chap_completed: bool,
    pub allowed_initiators: Option<Vec<String>>,
}

impl Default for SessionData {
    fn default() -> Self {
        SessionData {
            isid: [0u8; 6],
            tsih: 0,
            cid: 0,
            session_type: SessionType::Normal,
            params: SessionParams::default(),
            exp_cmd_sn: 1,
            max_cmd_sn: 1,
            stat_sn: 0,
            current_stage: 0,
            next_stage: 0,
            pending_writes: HashMap::new(),
            next_ttt: 1,
            last_sense_data: None,
            auth_config: AuthConfig::None,
            chap_state: None,
            target_chap_state: None,
            chap_completed: false,
            allowed_initiators: None,
        }
    }
}

// =============================================================================
// Typestate Session
// =============================================================================

/// iSCSI Session with compile-time state tracking
///
/// The state parameter `S` determines which operations are available.
/// State transitions consume `self` and return a new session in the target state.
#[derive(Debug)]
pub struct TypestateSession<S: SessionState> {
    data: SessionData,
    _state: PhantomData<S>,
}

// =============================================================================
// Session in Free State
// =============================================================================

impl TypestateSession<Free> {
    /// Create a new session in Free state
    pub fn new() -> Self {
        TypestateSession {
            data: SessionData::default(),
            _state: PhantomData,
        }
    }

    /// Configure authentication
    pub fn with_auth(mut self, auth_config: AuthConfig) -> Self {
        self.data.auth_config = auth_config;
        self
    }

    /// Configure allowed initiators (ACL)
    pub fn with_allowed_initiators(mut self, initiators: Option<Vec<String>>) -> Self {
        self.data.allowed_initiators = initiators;
        self
    }

    /// Process first login request and transition to SecurityNegotiation
    ///
    /// This method is ONLY available on TypestateSession<Free>
    /// Attempting to call it on any other state is a compile error.
    pub fn process_first_login(
        mut self,
        pdu: &IscsiPdu,
        target_name: &str,
    ) -> Result<LoginResult<SecurityNegotiation>, LoginError<Free>> {
        let login = match pdu.parse_login_request() {
            Ok(l) => l,
            Err(e) => return Err(LoginError::new(self, e)),
        };

        // Initialize session from first login
        self.data.isid = login.isid;
        self.data.cid = login.cid;
        self.data.exp_cmd_sn = login.cmd_sn;
        self.data.max_cmd_sn = login.cmd_sn + 1;
        self.data.params.target_name = target_name.to_string();
        self.data.current_stage = login.csg;
        self.data.next_stage = login.nsg;

        // Apply initiator parameters
        for (key, value) in &login.parameters {
            apply_initiator_param(&mut self.data, key, value);
        }

        // Transition to SecurityNegotiation
        let session: TypestateSession<SecurityNegotiation> = TypestateSession {
            data: self.data,
            _state: PhantomData,
        };

        Ok(LoginResult::Continue(session))
    }
}

impl Default for TypestateSession<Free> {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Session in SecurityNegotiation State
// =============================================================================

impl TypestateSession<SecurityNegotiation> {
    /// Process login during security negotiation
    ///
    /// Returns either:
    /// - `Continue(session)` - stay in SecurityNegotiation
    /// - `TransitionToLoginOp(session)` - move to LoginOperationalNegotiation
    /// - `TransitionToFullFeature(session)` - move directly to FullFeaturePhase
    pub fn process_security_login(
        mut self,
        pdu: &IscsiPdu,
        _target_name: &str,
    ) -> Result<SecurityLoginResult, LoginError<SecurityNegotiation>> {
        let login = match pdu.parse_login_request() {
            Ok(l) => l,
            Err(e) => return Err(LoginError::new(self, e)),
        };

        let itt = pdu.itt;

        // Apply parameters
        for (key, value) in &login.parameters {
            apply_initiator_param(&mut self.data, key, value);
        }

        // Handle CHAP authentication
        let (auth_complete, auth_params) = handle_chap_auth(&mut self.data, &login.parameters)?;

        // If auth not complete, stay in SecurityNegotiation
        if !auth_complete || !auth_params.is_empty() {
            let response = create_security_response(&self.data, &login, itt, &auth_params);
            return Ok(SecurityLoginResult::Continue {
                session: self,
                response,
            });
        }

        // Auth complete - check if initiator wants to transition
        if login.transit {
            match (login.csg, login.nsg) {
                (0, 1) => {
                    // Security -> LoginOperationalNegotiation
                    let response = create_transition_response(&self.data, &login, itt);
                    Ok(SecurityLoginResult::TransitionToLoginOp {
                        session: self.into_login_op_negotiation(),
                        response,
                    })
                }
                (0, 3) => {
                    // Security -> FullFeaturePhase (direct)
                    let mut session = self.into_full_feature();
                    if session.data.session_type == SessionType::Normal {
                        session.data.tsih = generate_tsih();
                    }
                    let response = create_final_login_response(&session.data, &login, itt);
                    Ok(SecurityLoginResult::TransitionToFullFeature {
                        session,
                        response,
                    })
                }
                _ => {
                    // Invalid transition - stay in current state
                    let response = create_security_response(&self.data, &login, itt, &[]);
                    Ok(SecurityLoginResult::Continue {
                        session: self,
                        response,
                    })
                }
            }
        } else {
            let response = create_security_response(&self.data, &login, itt, &[]);
            Ok(SecurityLoginResult::Continue {
                session: self,
                response,
            })
        }
    }

    /// Transition to LoginOperationalNegotiation
    fn into_login_op_negotiation(self) -> TypestateSession<LoginOperationalNegotiation> {
        TypestateSession {
            data: self.data,
            _state: PhantomData,
        }
    }

    /// Transition directly to FullFeaturePhase
    fn into_full_feature(self) -> TypestateSession<FullFeaturePhase> {
        TypestateSession {
            data: self.data,
            _state: PhantomData,
        }
    }

    /// Transition to Failed state (consumes self)
    pub fn fail(self, _reason: &str) -> TypestateSession<Failed> {
        TypestateSession {
            data: self.data,
            _state: PhantomData,
        }
    }
}

/// Result of processing a login during security negotiation
pub enum SecurityLoginResult {
    /// Stay in SecurityNegotiation (e.g., CHAP in progress)
    Continue {
        session: TypestateSession<SecurityNegotiation>,
        response: IscsiPdu,
    },
    /// Transition to LoginOperationalNegotiation
    TransitionToLoginOp {
        session: TypestateSession<LoginOperationalNegotiation>,
        response: IscsiPdu,
    },
    /// Transition directly to FullFeaturePhase
    TransitionToFullFeature {
        session: TypestateSession<FullFeaturePhase>,
        response: IscsiPdu,
    },
}

// =============================================================================
// Session in LoginOperationalNegotiation State
// =============================================================================

impl TypestateSession<LoginOperationalNegotiation> {
    /// Process login during operational negotiation
    pub fn process_login_op(
        mut self,
        pdu: &IscsiPdu,
        _target_name: &str,
    ) -> Result<LoginOpResult, LoginError<LoginOperationalNegotiation>> {
        let login = match pdu.parse_login_request() {
            Ok(l) => l,
            Err(e) => return Err(LoginError::new(self, e)),
        };

        let itt = pdu.itt;

        // Apply parameters
        for (key, value) in &login.parameters {
            apply_initiator_param(&mut self.data, key, value);
        }

        if login.transit && login.nsg == 3 {
            // Transition to FullFeaturePhase
            let mut session = self.into_full_feature();
            if session.data.session_type == SessionType::Normal {
                session.data.tsih = generate_tsih();
            }
            let response = create_final_login_response(&session.data, &login, itt);
            Ok(LoginOpResult::TransitionToFullFeature { session, response })
        } else {
            let response = create_login_op_response(&self.data, &login, itt);
            Ok(LoginOpResult::Continue {
                session: self,
                response,
            })
        }
    }

    fn into_full_feature(self) -> TypestateSession<FullFeaturePhase> {
        TypestateSession {
            data: self.data,
            _state: PhantomData,
        }
    }

    /// Transition to Failed state
    pub fn fail(self, _reason: &str) -> TypestateSession<Failed> {
        TypestateSession {
            data: self.data,
            _state: PhantomData,
        }
    }
}

/// Result of processing a login during operational negotiation
pub enum LoginOpResult {
    Continue {
        session: TypestateSession<LoginOperationalNegotiation>,
        response: IscsiPdu,
    },
    TransitionToFullFeature {
        session: TypestateSession<FullFeaturePhase>,
        response: IscsiPdu,
    },
}

// =============================================================================
// Session in FullFeaturePhase State
// =============================================================================

impl TypestateSession<FullFeaturePhase> {
    /// Check if this is a discovery session
    pub fn is_discovery(&self) -> bool {
        self.data.session_type == SessionType::Discovery
    }

    /// Get mutable access to session data for SCSI command processing
    pub fn data_mut(&mut self) -> &mut SessionData {
        &mut self.data
    }

    /// Get immutable access to session data
    pub fn data(&self) -> &SessionData {
        &self.data
    }

    /// Get next StatSN and increment
    pub fn next_stat_sn(&mut self) -> u32 {
        let sn = self.data.stat_sn;
        self.data.stat_sn = self.data.stat_sn.wrapping_add(1);
        sn
    }

    /// Validate command sequence number
    pub fn validate_cmd_sn(&mut self, cmd_sn: u32) -> bool {
        let in_window = sn_in_window(cmd_sn, self.data.exp_cmd_sn, self.data.max_cmd_sn);
        if in_window && cmd_sn == self.data.exp_cmd_sn {
            self.data.exp_cmd_sn = self.data.exp_cmd_sn.wrapping_add(1);
            self.data.max_cmd_sn = self.data.max_cmd_sn.wrapping_add(1);
        }
        in_window
    }

    /// Process NOP-Out (ping) request
    ///
    /// This method is ONLY available on TypestateSession<FullFeaturePhase>
    pub fn process_nop_out(&mut self, pdu: &IscsiPdu) -> ScsiResult<IscsiPdu> {
        let nop = pdu.parse_nop_out()?;

        if nop.itt == 0xFFFF_FFFF {
            return Err(IscsiError::Protocol("Unsolicited NOP-Out response".to_string()));
        }

        Ok(IscsiPdu::nop_in(
            nop.itt,
            0xFFFF_FFFF,
            self.next_stat_sn(),
            self.data.exp_cmd_sn,
            self.data.max_cmd_sn,
            nop.lun,
        ))
    }

    /// Process logout request - transitions to Logout state
    ///
    /// Note: This consumes self and returns a new session in Logout state
    pub fn process_logout(mut self, pdu: &IscsiPdu) -> ScsiResult<(TypestateSession<Logout>, IscsiPdu)> {
        let logout = pdu.parse_logout_request()?;

        let response = IscsiPdu::logout_response(
            logout.itt,
            self.next_stat_sn(),
            self.data.exp_cmd_sn,
            self.data.max_cmd_sn,
            pdu::logout_response::SUCCESS,
            self.data.params.default_time2wait,
            self.data.params.default_time2retain,
        );

        let logout_session: TypestateSession<Logout> = TypestateSession {
            data: self.data,
            _state: PhantomData,
        };

        Ok((logout_session, response))
    }

    /// Transition to Failed state
    pub fn fail(self, _reason: &str) -> TypestateSession<Failed> {
        TypestateSession {
            data: self.data,
            _state: PhantomData,
        }
    }

    /// Handle SendTargets discovery request
    pub fn handle_send_targets(&self, target_name: &str, target_address: &str) -> Vec<(String, String)> {
        vec![
            ("TargetName".to_string(), target_name.to_string()),
            ("TargetAddress".to_string(), format!("{},1", target_address)),
        ]
    }
}

// =============================================================================
// Session in Logout State
// =============================================================================

impl TypestateSession<Logout> {
    /// Session has completed logout - can only be dropped
    pub fn is_complete(&self) -> bool {
        true
    }
}

// =============================================================================
// Session in Failed State
// =============================================================================

impl TypestateSession<Failed> {
    /// Get error information
    pub fn is_failed(&self) -> bool {
        true
    }
}

// =============================================================================
// Login Error with State Recovery
// =============================================================================

/// Error during login that preserves session state for recovery
pub struct LoginError<S: SessionState> {
    /// The session in its current state (for error recovery)
    pub session: TypestateSession<S>,
    /// The error that occurred
    pub error: IscsiError,
}

impl<S: SessionState> LoginError<S> {
    fn new(session: TypestateSession<S>, error: IscsiError) -> Self {
        LoginError { session, error }
    }
}

// =============================================================================
// Login Result Types
// =============================================================================

/// Result of processing a login in Free state
pub enum LoginResult<S: SessionState> {
    /// Continue in new state
    Continue(TypestateSession<S>),
    /// Login rejected
    Rejected { response: IscsiPdu },
}

// =============================================================================
// Helper Functions
// =============================================================================

fn apply_initiator_param(data: &mut SessionData, key: &str, value: &str) {
    match key {
        "InitiatorName" => data.params.initiator_name = value.to_string(),
        "InitiatorAlias" => data.params.initiator_alias = value.to_string(),
        "TargetName" => data.params.target_name = value.to_string(),
        "SessionType" => {
            data.session_type = match value {
                "Discovery" => SessionType::Discovery,
                _ => SessionType::Normal,
            };
        }
        "MaxRecvDataSegmentLength" => {
            if let Ok(v) = value.parse::<u32>() {
                data.params.max_xmit_data_segment_length = v;
            }
        }
        "MaxBurstLength" => {
            if let Ok(v) = value.parse::<u32>() {
                data.params.max_burst_length = v.min(data.params.max_burst_length);
            }
        }
        "FirstBurstLength" => {
            if let Ok(v) = value.parse::<u32>() {
                data.params.first_burst_length = v.min(data.params.first_burst_length);
            }
        }
        "ImmediateData" => {
            data.params.immediate_data = data.params.immediate_data && (value == "Yes");
        }
        "InitialR2T" => {
            data.params.initial_r2t = data.params.initial_r2t || (value == "Yes");
        }
        _ => {}
    }
}

fn handle_chap_auth(
    data: &mut SessionData,
    params: &[(String, String)],
) -> Result<(bool, Vec<(String, String)>), LoginError<SecurityNegotiation>> {
    // Simplified CHAP handling - in real implementation, this would
    // contain the full CHAP state machine
    match &data.auth_config {
        AuthConfig::None => Ok((true, vec![])),
        AuthConfig::Chap { .. } | AuthConfig::MutualChap { .. } => {
            // Check if CHAP completed
            if data.chap_completed {
                Ok((true, vec![]))
            } else {
                // Would handle CHAP challenge/response here
                // For now, just mark as complete if no auth params in request
                let has_auth = params.iter().any(|(k, _)| k.starts_with("CHAP_") || k == "AuthMethod");
                if !has_auth && data.chap_state.is_some() {
                    data.chap_completed = true;
                    Ok((true, vec![]))
                } else {
                    // Return CHAP parameters
                    Ok((false, vec![("AuthMethod".to_string(), "CHAP".to_string())]))
                }
            }
        }
    }
}

fn create_security_response(data: &SessionData, login: &LoginRequest, itt: u32, auth_params: &[(String, String)]) -> IscsiPdu {
    let response_data = serialize_text_parameters(auth_params);

    IscsiPdu::login_response(
        data.isid,
        data.tsih,
        data.stat_sn,
        data.exp_cmd_sn,
        data.max_cmd_sn,
        pdu::login_status::SUCCESS,
        0,
        login.csg,
        login.nsg,
        false,
        itt,
        response_data,
    )
}

fn create_transition_response(data: &SessionData, login: &LoginRequest, itt: u32) -> IscsiPdu {
    IscsiPdu::login_response(
        data.isid,
        data.tsih,
        data.stat_sn,
        data.exp_cmd_sn,
        data.max_cmd_sn,
        pdu::login_status::SUCCESS,
        0,
        login.csg,
        login.nsg,
        true,
        itt,
        vec![],
    )
}

fn create_login_op_response(data: &SessionData, login: &LoginRequest, itt: u32) -> IscsiPdu {
    IscsiPdu::login_response(
        data.isid,
        data.tsih,
        data.stat_sn,
        data.exp_cmd_sn,
        data.max_cmd_sn,
        pdu::login_status::SUCCESS,
        0,
        login.csg,
        login.nsg,
        false,
        itt,
        vec![],
    )
}

fn create_final_login_response(data: &SessionData, login: &LoginRequest, itt: u32) -> IscsiPdu {
    let response_params = generate_response_params(data);
    let response_data = serialize_text_parameters(&response_params);

    IscsiPdu::login_response(
        data.isid,
        data.tsih,
        data.stat_sn,
        data.exp_cmd_sn,
        data.max_cmd_sn,
        pdu::login_status::SUCCESS,
        0,
        login.csg,
        login.nsg,
        true,
        itt,
        response_data,
    )
}

fn generate_response_params(data: &SessionData) -> Vec<(String, String)> {
    vec![
        ("MaxRecvDataSegmentLength".to_string(), data.params.max_recv_data_segment_length.to_string()),
        ("MaxBurstLength".to_string(), data.params.max_burst_length.to_string()),
        ("FirstBurstLength".to_string(), data.params.first_burst_length.to_string()),
        ("ImmediateData".to_string(), if data.params.immediate_data { "Yes" } else { "No" }.to_string()),
        ("InitialR2T".to_string(), if data.params.initial_r2t { "Yes" } else { "No" }.to_string()),
    ]
}

fn generate_tsih() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    ((duration.as_millis() & 0xFFFF) as u16).max(1)
}

fn sn_in_window(sn: u32, exp_sn: u32, max_sn: u32) -> bool {
    let diff_exp = sn.wrapping_sub(exp_sn) as i32;
    let diff_max = max_sn.wrapping_sub(sn) as i32;
    diff_exp >= 0 && diff_max >= 0
}

// =============================================================================
// Session State Wrapper for Runtime Dispatch
// =============================================================================

/// A wrapper enum for when runtime dispatch is needed
/// (e.g., storing sessions in a collection)
pub enum AnySession {
    Free(TypestateSession<Free>),
    SecurityNegotiation(TypestateSession<SecurityNegotiation>),
    LoginOperationalNegotiation(TypestateSession<LoginOperationalNegotiation>),
    FullFeaturePhase(TypestateSession<FullFeaturePhase>),
    Logout(TypestateSession<Logout>),
    Failed(TypestateSession<Failed>),
}

impl AnySession {
    /// Create a new session
    pub fn new() -> Self {
        AnySession::Free(TypestateSession::new())
    }

    /// Check if session is in full feature phase
    pub fn is_full_feature(&self) -> bool {
        matches!(self, AnySession::FullFeaturePhase(_))
    }

    /// Check if session has ended
    pub fn is_ended(&self) -> bool {
        matches!(self, AnySession::Logout(_) | AnySession::Failed(_))
    }
}

impl Default for AnySession {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_typestate_creation() {
        let session: TypestateSession<Free> = TypestateSession::new();
        // This compiles - new() returns TypestateSession<Free>
        assert_eq!(session.data.tsih, 0);
    }

    #[test]
    fn test_typestate_compile_time_safety() {
        let session: TypestateSession<Free> = TypestateSession::new();

        // These would NOT compile (uncomment to verify):

        // session.process_nop_out(&pdu);  // Error: method not found for TypestateSession<Free>
        // session.process_logout(&pdu);   // Error: method not found for TypestateSession<Free>

        // Only process_first_login is available on Free state
        // This is the key benefit: the compiler enforces state-appropriate operations
        let _ = session;
    }

    #[test]
    fn test_full_feature_operations() {
        // Simulate a session that has transitioned to FullFeaturePhase
        let session: TypestateSession<FullFeaturePhase> = TypestateSession {
            data: SessionData::default(),
            _state: PhantomData,
        };

        // These methods ARE available on FullFeaturePhase
        assert!(!session.is_discovery());

        // This would compile - process_logout is available
        // let (logout_session, response) = session.process_logout(&pdu)?;
        // After logout, the session is TypestateSession<Logout>
        // and process_nop_out would no longer be available
    }

    #[test]
    fn test_state_transitions() {
        // Demonstrate the state flow
        let free: TypestateSession<Free> = TypestateSession::new();

        // Can only call process_first_login on Free
        // After that, we get SecurityNegotiation

        // Then from SecurityNegotiation, we can transition to:
        // - LoginOperationalNegotiation (via TransitionToLoginOp)
        // - FullFeaturePhase (via TransitionToFullFeature)

        // From FullFeaturePhase:
        // - process_logout() -> Logout
        // - fail() -> Failed

        // The type system enforces all of this at compile time!
        let _ = free;
    }

    #[test]
    fn test_any_session_wrapper() {
        // For cases where we need runtime dispatch
        let any_session = AnySession::new();
        assert!(!any_session.is_full_feature());
        assert!(!any_session.is_ended());
    }
}
