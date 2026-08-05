//! Focused scaffold for the disabled-by-default O5 operator composition path.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use buzz_relay::{
    api::operator::lifecycle_router,
    operator_runtime::{
        AuthorizedOperatorOperation, DurableOperatorExecutor, GrantedOperatorCapability,
        OpaqueOperatorReference, OperatorAction, OperatorAuthenticator,
        OperatorAuthorizationRequest, OperatorCapability, OperatorClock, OperatorCredential,
        OperatorOutcome, OperatorOutcomeStatus, OperatorRecord, OperatorRecordState,
        OperatorRuntime, OperatorRuntimeError,
    },
};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

const CREDENTIAL_CANARY: &str = "Synthetic operator credential must never escape";
const PRIVATE_CLAIM_CANARY: &str = "Synthetic private claim must never escape";

struct FixedClock;

impl OperatorClock for FixedClock {
    fn now_unix_seconds(&self) -> Result<u64, OperatorRuntimeError> {
        Ok(100)
    }
}

struct TestGrant {
    domain_id: Uuid,
    operation_id: Uuid,
    intent_fingerprint: [u8; 32],
    allow: bool,
}

impl GrantedOperatorCapability for TestGrant {
    fn domain_id(&self) -> Uuid {
        self.domain_id
    }

    fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    fn intent_fingerprint(&self) -> [u8; 32] {
        self.intent_fingerprint
    }

    fn actor_reference(&self) -> OpaqueOperatorReference {
        OpaqueOperatorReference::from_digest([1; 32])
    }

    fn provenance_reference(&self) -> OpaqueOperatorReference {
        OpaqueOperatorReference::from_digest([2; 32])
    }

    fn expires_at_unix_seconds(&self) -> u64 {
        200
    }

    fn permits(&self, _capability: OperatorCapability) -> bool {
        self.allow
    }
}

struct TestAuthenticator {
    allow: bool,
    calls: Mutex<Vec<OperatorAuthorizationRequest>>,
}

#[async_trait]
impl OperatorAuthenticator for TestAuthenticator {
    async fn authenticate(
        &self,
        credential: &OperatorCredential,
        request: OperatorAuthorizationRequest,
    ) -> Result<Box<dyn GrantedOperatorCapability>, OperatorRuntimeError> {
        assert_eq!(
            credential.expose_to_authenticator(),
            CREDENTIAL_CANARY.as_bytes()
        );
        assert_ne!(request.intent_fingerprint(), [0; 32]);
        self.calls.lock().expect("auth calls").push(request);
        Ok(Box::new(TestGrant {
            domain_id: request.domain_id(),
            operation_id: request.operation_id(),
            intent_fingerprint: request.intent_fingerprint(),
            allow: self.allow,
        }))
    }
}

#[derive(Default)]
struct TestExecutor {
    receipts: Mutex<HashMap<(Uuid, Uuid), ([u8; 32], OperatorOutcome)>>,
    committed_actions: Mutex<Vec<OperatorAction>>,
}

#[async_trait]
impl DurableOperatorExecutor for TestExecutor {
    async fn execute_idempotent(
        &self,
        operation: AuthorizedOperatorOperation,
    ) -> Result<OperatorOutcome, OperatorRuntimeError> {
        let invocation = operation.invocation();
        let context = invocation.context();
        let action = invocation.intent().action();
        let fingerprint = invocation.fingerprint();
        let receipt_key = (context.domain_id(), context.operation_id());
        let mut receipts = self.receipts.lock().expect("receipts");
        if let Some((existing_fingerprint, outcome)) = receipts.get(&receipt_key) {
            return if *existing_fingerprint == fingerprint {
                Ok(outcome.clone())
            } else {
                Err(OperatorRuntimeError::IdempotencyConflict)
            };
        }

        assert_ne!(operation.actor_reference().digest(), [0; 32]);
        assert_ne!(operation.provenance_reference().digest(), [0; 32]);
        let (status, affected_count, records) = match action {
            OperatorAction::List => (
                OperatorOutcomeStatus::Listed,
                1,
                vec![OperatorRecord {
                    reference: OpaqueOperatorReference::from_digest([7; 32]),
                    state: OperatorRecordState::Active,
                    revision: context.expected_revision(),
                }],
            ),
            OperatorAction::Preview => (OperatorOutcomeStatus::Previewed, 1, Vec::new()),
            OperatorAction::Revoke => (OperatorOutcomeStatus::Revoked, 1, Vec::new()),
            OperatorAction::Rotate => (OperatorOutcomeStatus::Rotated, 1, Vec::new()),
        };
        let outcome = OperatorOutcome::new(
            context.operation_id(),
            context.correlation_id(),
            action,
            status,
            affected_count,
            context.expected_revision() + 1,
            records,
        )?;
        receipts.insert(receipt_key, (fingerprint, outcome.clone()));
        self.committed_actions
            .lock()
            .expect("committed actions")
            .push(action);
        Ok(outcome)
    }
}

fn runtime() -> (
    Arc<OperatorRuntime>,
    Arc<TestAuthenticator>,
    Arc<TestExecutor>,
) {
    runtime_with_capability(true)
}

fn runtime_with_capability(
    allow: bool,
) -> (
    Arc<OperatorRuntime>,
    Arc<TestAuthenticator>,
    Arc<TestExecutor>,
) {
    let authenticator = Arc::new(TestAuthenticator {
        allow,
        calls: Mutex::new(Vec::new()),
    });
    let executor = Arc::new(TestExecutor::default());
    let runtime = Arc::new(OperatorRuntime::new(
        authenticator.clone(),
        executor.clone(),
        Arc::new(FixedClock),
    ));
    (runtime, authenticator, executor)
}

fn reference(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn request_body(domain_id: Uuid, operation_id: Uuid, correlation_id: Uuid) -> Value {
    json!({
        "domain_id": domain_id,
        "operation_id": operation_id,
        "correlation_id": correlation_id,
        "reason": "planned_rotation",
        "expected_revision": 7,
        "approval_references": [reference(9)],
        "private_claim_canary": PRIVATE_CLAIM_CANARY,
    })
}

async fn post(runtime: Arc<OperatorRuntime>, path: &str, body: Value) -> (StatusCode, String) {
    let response = lifecycle_router(runtime)
        .oneshot(
            Request::post(path)
                .header(header::AUTHORIZATION, CREDENTIAL_CANARY)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("operator request"),
        )
        .await
        .expect("operator response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("response body");
    (
        status,
        String::from_utf8(bytes.to_vec()).expect("UTF-8 response"),
    )
}

#[tokio::test]
async fn real_composition_path_reaches_list_preview_revoke_and_rotate() {
    let (runtime, authenticator, executor) = runtime();
    let domain_id = Uuid::from_u128(0x501);
    let mut results = Vec::new();

    let mut list = request_body(domain_id, Uuid::from_u128(0x510), Uuid::from_u128(0x610));
    list["limit"] = json!(25);
    results.push(post(runtime.clone(), "/operator/v1/lifecycle/list", list.clone()).await);

    let mut preview = request_body(domain_id, Uuid::from_u128(0x511), Uuid::from_u128(0x611));
    preview["target"] = json!(reference(3));
    preview["replacement"] = json!(reference(4));
    results.push(post(runtime.clone(), "/operator/v1/lifecycle/preview", preview).await);

    let mut revoke = request_body(domain_id, Uuid::from_u128(0x512), Uuid::from_u128(0x612));
    revoke["target"] = json!(reference(3));
    results.push(post(runtime.clone(), "/operator/v1/lifecycle/revoke", revoke).await);

    let mut rotate = request_body(domain_id, Uuid::from_u128(0x513), Uuid::from_u128(0x613));
    rotate["target"] = json!(reference(3));
    rotate["replacement"] = json!(reference(4));
    results.push(post(runtime.clone(), "/operator/v1/lifecycle/rotate", rotate).await);

    // The same semantic operation returns the original result.
    results.push(post(runtime, "/operator/v1/lifecycle/list", list).await);

    for (status, body) in &results {
        assert_eq!(*status, StatusCode::OK, "unexpected body: {body}");
        assert!(!body.contains(CREDENTIAL_CANARY));
        assert!(!body.contains(PRIVATE_CLAIM_CANARY));
    }
    assert_eq!(authenticator.calls.lock().expect("auth calls").len(), 5);

    let actions = executor
        .committed_actions
        .lock()
        .expect("committed actions")
        .clone();
    assert_eq!(actions.len(), 4, "idempotent replay must not re-execute");
    for expected in [
        OperatorAction::List,
        OperatorAction::Preview,
        OperatorAction::Revoke,
        OperatorAction::Rotate,
    ] {
        assert!(actions.contains(&expected), "missing {expected:?}");
    }
}

#[tokio::test]
async fn conflicting_operation_replay_is_denied_without_second_execution() {
    let (runtime, _authenticator, executor) = runtime();
    let domain_id = Uuid::from_u128(0x520);
    let operation_id = Uuid::from_u128(0x521);
    let correlation_id = Uuid::from_u128(0x522);
    let mut first = request_body(domain_id, operation_id, correlation_id);
    first["target"] = json!(reference(3));
    assert_eq!(
        post(runtime.clone(), "/operator/v1/lifecycle/revoke", first,)
            .await
            .0,
        StatusCode::OK
    );

    let mut conflicting = request_body(domain_id, operation_id, correlation_id);
    conflicting["target"] = json!(reference(5));
    let (status, body) = post(runtime, "/operator/v1/lifecycle/revoke", conflicting).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body.contains("operator_idempotency_conflict"));
    assert_eq!(
        executor
            .committed_actions
            .lock()
            .expect("committed actions")
            .len(),
        1
    );
}

#[tokio::test]
async fn missing_credential_and_missing_capability_never_reach_executor() {
    let (runtime, _authenticator, executor) = runtime_with_capability(false);
    let domain_id = Uuid::from_u128(0x530);
    let mut body = request_body(domain_id, Uuid::from_u128(0x531), Uuid::from_u128(0x532));
    body["target"] = json!(reference(3));

    let missing = lifecycle_router(runtime.clone())
        .oneshot(
            Request::post("/operator/v1/lifecycle/revoke")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("missing-credential request"),
        )
        .await
        .expect("missing-credential response");
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let (status, response) = post(runtime, "/operator/v1/lifecycle/revoke", body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(response.contains("operator_capability_missing"));
    assert!(executor
        .committed_actions
        .lock()
        .expect("committed actions")
        .is_empty());
}

#[test]
fn stock_router_does_not_register_lifecycle_surface() {
    let stock_router = include_str!("../src/router.rs");
    assert!(!stock_router.contains("lifecycle_router"));
    assert!(!stock_router.contains("/operator/v1/lifecycle"));
}
