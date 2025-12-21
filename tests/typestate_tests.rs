//! Typestate enforcement tests
//!
//! This module tests that the typestate pattern correctly prevents
//! authentication bypass at compile time.

use iscsi_target::typestate_session::{
    AnySession, Free, FullFeaturePhase, SessionData, TypestateSession,
};
use std::marker::PhantomData;

/// Test: Verify that you CANNOT bypass authentication by directly constructing
/// a TypestateSession<FullFeaturePhase>.
///
/// This test demonstrates the SECURITY VULNERABILITY if the struct fields
/// are not properly protected.
#[test]
fn test_cannot_bypass_authentication_via_direct_construction() {
    // VULNERABILITY: If this compiles, the typestate pattern is broken!
    // An attacker could skip login entirely and create a FullFeaturePhase session.
    //
    // The following code SHOULD NOT COMPILE if typestate is properly enforced:
    //
    // let session: TypestateSession<FullFeaturePhase> = TypestateSession {
    //     data: SessionData::default(),
    //     _state: PhantomData,
    // };
    //
    // If we can construct this, we can call session.process_nop_out() without login!

    // For now, this test just documents the expected behavior.
    // If the vulnerability exists, we need to fix it.

    // The ONLY way to get a TypestateSession<FullFeaturePhase> should be:
    // 1. Start with TypestateSession<Free>::new()
    // 2. Go through the login process (process_login)
    // 3. Complete authentication
    // 4. Receive a TypestateSession<FullFeaturePhase> from the state machine

    // Using AnySession, which provides runtime safety:
    let any_session = AnySession::new();
    assert!(!any_session.is_full_feature());
    assert!(any_session.is_login_phase());
}

/// Test: The proper way to create sessions goes through Free state
#[test]
fn test_proper_session_creation_path() {
    // Correct: Start in Free state
    let free_session: TypestateSession<Free> = TypestateSession::new();
    assert_eq!(free_session.data.tsih, 0);

    // To get to FullFeaturePhase, you MUST call process_login
    // which requires a valid PDU and goes through authentication
}

/// Test: AnySession provides runtime checks (fallback safety)
#[test]
fn test_anysession_runtime_checks() {
    let mut any_session = AnySession::new();

    // Trying to call process_nop_out on a Free session fails at runtime
    // This is the fallback safety - not as good as compile-time, but safe
    let result = any_session.process_nop_out(&iscsi_target::pdu::IscsiPdu::default());
    assert!(result.is_err());
    if let Err(e) = result {
        let msg = format!("{}", e);
        assert!(msg.contains("FullFeaturePhase"));
    }
}

/// Test: Sealed trait prevents external state implementations
/// The following would fail to compile because private::Sealed is not accessible:
/// ```compile_fail
/// struct MyCustomState;
/// impl iscsi_target::typestate_session::SessionState for MyCustomState {}
/// ```
#[test]
fn test_sealed_trait_documentation() {
    // This test just documents that external types cannot implement SessionState
    // because the Sealed trait is in a private module
}

/// Compile-time enforcement verification
///
/// The following would fail to compile because TypestateSession<Free>
/// does not have a process_nop_out method:
/// ```compile_fail
/// use iscsi_target::typestate_session::{TypestateSession, Free};
/// let session: TypestateSession<Free> = TypestateSession::new();
/// session.process_nop_out(&Default::default()); // ERROR: method not found
/// ```
#[test]
fn test_compile_time_method_enforcement_documentation() {
    // This test documents that calling process_nop_out on TypestateSession<Free>
    // is a compile-time error, not a runtime error
}

/// CRITICAL TEST: Attempt to bypass authentication via direct construction
///
/// This test SHOULD FAIL TO COMPILE if typestate is properly enforced.
/// If this test compiles and runs, it means there's a security vulnerability.
///
/// ```compile_fail
/// use iscsi_target::typestate_session::{TypestateSession, FullFeaturePhase, SessionData};
/// use std::marker::PhantomData;
///
/// // This should NOT compile - bypassing authentication!
/// let session: TypestateSession<FullFeaturePhase> = TypestateSession {
///     data: SessionData::default(),
///     _state: PhantomData,
/// };
/// ```
#[test]
fn test_auth_bypass_should_not_compile() {
    // If the compile_fail doctest above compiles, we have a vulnerability.
    // This test exists to document the expected behavior.
}

/// VERIFIED: Direct construction bypass is BLOCKED by private `_state` field.
///
/// The following code fails to compile with:
/// "error[E0451]: field `_state` of struct `TypestateSession` is private"
///
/// This confirms the typestate pattern is properly enforced at compile-time.
/// ```compile_fail
/// use iscsi_target::typestate_session::{TypestateSession, FullFeaturePhase, SessionData};
/// use std::marker::PhantomData;
///
/// // BLOCKED: Cannot bypass authentication via direct construction
/// let bypassed_session: TypestateSession<FullFeaturePhase> = TypestateSession {
///     data: SessionData::default(),
///     _state: PhantomData,  // ERROR: field `_state` is private
/// };
/// ```
#[test]
fn test_bypass_blocked_by_private_field() {
    // VERIFIED: The `_state` field is private, preventing direct construction.
    // External code cannot create TypestateSession<FullFeaturePhase> without
    // going through the proper login state machine.
    //
    // The only way to get FullFeaturePhase is:
    // 1. TypestateSession::<Free>::new()
    // 2. .process_login() -> SecurityNegotiation
    // 3. Complete CHAP authentication
    // 4. Transition to FullFeaturePhase
}
