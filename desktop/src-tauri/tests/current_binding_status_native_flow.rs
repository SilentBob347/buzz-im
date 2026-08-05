//! Real loopback transport coverage for the native current-binding projection.
//!
//! This integration target deliberately includes the production session fold instead of
//! recreating its validation or projection DTO. The relay half is synthetic and loopback-only;
//! every delivered event still crosses an actual WebSocket before the production fold sees it.

#[path = "../src/client_binding_status_session.rs"]
mod client_binding_status_session;

use std::{env, path::PathBuf, time::Duration};

use buzz_core_pkg::{
    client_binding_bootstrap::{
        ClientBindingBootstrapInputV1, ClientBindingEpoch, CLIENT_BINDING_BOOTSTRAP_SUB_ID,
        CLIENT_BINDING_STATUS_SUB_ID,
    },
    client_binding_status::ClientBindingStatusInputV1,
    kind::{KIND_CLIENT_BINDING_STATUS, KIND_USER_TRUSTED_ASSERTION},
    CommunityId,
};
use client_binding_status_session::{
    ClientBindingStatusSession, CurrentProjection, ProjectionUpdate,
};
use futures_util::{SinkExt, StreamExt};
use nostr::{Event, EventBuilder, Keys, Kind, PublicKey, Tag, Timestamp};
use serde::Serialize;
use serde_json::json;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    accept_async, connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream,
};
use uuid::Uuid;

const NOW: u64 = 2_000_000_000;
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(2);
const ORDINARY_SUB_ID: &str = "synthetic-ordinary-events";

type ClientSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;
type RelaySocket = WebSocketStream<TcpStream>;

#[derive(Serialize)]
struct ProjectionTrace {
    version: u64,
    steps: Vec<TraceStep>,
}

#[derive(Serialize)]
struct TraceStep {
    case: &'static str,
    // This is the production DTO, not a test-owned projection lookalike.
    projection: Option<CurrentProjection>,
}

impl ProjectionTrace {
    fn new() -> Self {
        Self {
            version: 1,
            steps: Vec::new(),
        }
    }

    fn record(&mut self, case: &'static str, flow: &NativeFlow) {
        self.steps.push(TraceStep {
            case,
            projection: flow.projection.clone(),
        });
    }

    fn assert_contract_and_export_if_requested(&self) {
        let value = serde_json::to_value(self).expect("production projection trace serializes");
        let steps = value["steps"].as_array().expect("trace steps are an array");
        for step in steps {
            if let Some(projection) = step["projection"].as_object() {
                let mut keys = projection.keys().map(String::as_str).collect::<Vec<_>>();
                keys.sort_unstable();
                assert_eq!(
                    keys,
                    ["connectionEpoch", "eventAuthorPubkey", "freshUntil"],
                    "trace projection must remain the production current-only DTO",
                );
            }
        }

        let Some(raw_path) = env::var_os("BUZZ_J3C_PROJECTION_TRACE_OUT") else {
            return;
        };
        let path = PathBuf::from(raw_path);
        assert!(
            path.is_absolute(),
            "BUZZ_J3C_PROJECTION_TRACE_OUT must be an absolute test-artifact path"
        );
        let parent = path
            .parent()
            .expect("trace output must have a parent directory");
        std::fs::create_dir_all(parent).expect("create projection trace directory");
        let mut bytes = serde_json::to_vec_pretty(self).expect("serialize projection trace");
        bytes.push(b'\n');
        std::fs::write(&path, bytes).expect("write projection trace");
    }
}

struct NativeFlow {
    relay_socket: RelaySocket,
    client_socket: ClientSocket,
    session: ClientBindingStatusSession,
    projection: Option<CurrentProjection>,
}

impl NativeFlow {
    async fn connect(
        trusted_relay_pubkey: PublicKey,
        expected_author_pubkey: PublicKey,
        epoch: ClientBindingEpoch,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind synthetic relay to an OS-assigned loopback port");
        let address = listener.local_addr().expect("read synthetic relay address");
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);

        let relay = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept native client");
            assert!(peer.ip().is_loopback());
            accept_async(stream)
                .await
                .expect("accept WebSocket upgrade")
        });
        let (client_socket, response) = connect_async(format!("ws://{address}"))
            .await
            .expect("connect native loopback WebSocket");
        assert_eq!(response.status(), 101);
        let relay_socket = relay.await.expect("join synthetic relay accept task");

        Self {
            relay_socket,
            client_socket,
            session: ClientBindingStatusSession::new(
                trusted_relay_pubkey,
                expected_author_pubkey,
                epoch,
            ),
            projection: None,
        }
    }

    async fn send_reserved_event(&mut self, sub_id: &str, event: &Event, now: u64) {
        assert!(
            matches!(
                sub_id,
                CLIENT_BINDING_BOOTSTRAP_SUB_ID | CLIENT_BINDING_STATUS_SUB_ID
            ),
            "reserved helper requires an exact native-owned subscription id"
        );
        let consumed = self.send_event(sub_id, event, now).await;
        assert!(consumed, "production session must swallow reserved frames");
    }

    async fn send_ordinary_event(&mut self, event: &Event, now: u64) {
        let consumed = self.send_event(ORDINARY_SUB_ID, event, now).await;
        assert!(
            !consumed,
            "ordinary events must remain outside the status fold"
        );
    }

    async fn send_event(&mut self, sub_id: &str, event: &Event, now: u64) -> bool {
        let event_json = serde_json::to_value(event).expect("serialize synthetic Nostr event");
        let frame = json!(["EVENT", sub_id, event_json]).to_string();
        self.relay_socket
            .send(Message::Text(frame.into()))
            .await
            .expect("send synthetic relay frame");

        let message = tokio::time::timeout(RECEIVE_TIMEOUT, self.client_socket.next())
            .await
            .expect("native socket receives relay frame before timeout")
            .expect("native socket remains connected")
            .expect("native socket receives a valid WebSocket message");
        let text = match message {
            Message::Text(text) => text.to_string(),
            other => panic!("expected relay text frame, received {other:?}"),
        };
        let update = self.session.consume_text(&text, now);
        let consumed = update.is_some();
        if let Some(update) = update {
            self.apply(update);
        }
        consumed
    }

    fn expire(&mut self, now: u64) {
        let update = self.session.expire(now);
        self.apply(update);
    }

    async fn physical_disconnect(&mut self) {
        self.relay_socket
            .send(Message::Close(None))
            .await
            .expect("relay closes physical WebSocket");
        let message = tokio::time::timeout(RECEIVE_TIMEOUT, self.client_socket.next())
            .await
            .expect("native socket observes physical disconnect before timeout");
        assert!(
            matches!(message, Some(Ok(Message::Close(_))) | None),
            "native transport must observe a close frame or EOF"
        );
        let update = self.session.disconnect();
        self.apply(update);
    }

    fn apply(&mut self, update: ProjectionUpdate) {
        match update {
            ProjectionUpdate::Unchanged => {}
            ProjectionUpdate::Clear => self.projection = None,
            ProjectionUpdate::Current(projection) => self.projection = Some(projection),
        }
    }
}

fn random_epoch() -> ClientBindingEpoch {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).expect("generate synthetic connection epoch");
    ClientBindingEpoch::from_random_bytes(bytes)
}

fn random_domain() -> CommunityId {
    CommunityId::from_uuid(Uuid::new_v4())
}

fn bootstrap_event(
    relay: &Keys,
    domain: CommunityId,
    author: PublicKey,
    epoch: ClientBindingEpoch,
    issued_at: u64,
) -> Event {
    ClientBindingBootstrapInputV1::new(domain, author, epoch, issued_at)
        .expect("construct synthetic bootstrap")
        .sign_with_relay_keys(relay)
        .expect("sign synthetic bootstrap")
}

fn current_event(
    relay: &Keys,
    domain: CommunityId,
    author: PublicKey,
    revision: u64,
    issued_at: u64,
    fresh_until: u64,
) -> Event {
    ClientBindingStatusInputV1::current(
        domain,
        author,
        1,
        "policy.synthetic.example.invalid/v1",
        revision,
        issued_at,
        fresh_until,
        Some("Synthetic Example".to_string()),
    )
    .expect("construct synthetic current status")
    .sign_with_relay_keys(relay)
    .expect("sign synthetic current status")
}

fn withdrawal_event(
    relay: &Keys,
    domain: CommunityId,
    author: PublicKey,
    revision: u64,
    issued_at: u64,
    fresh_until: u64,
) -> Event {
    ClientBindingStatusInputV1::withdrawn(domain, author, revision, issued_at, fresh_until)
        .expect("construct synthetic withdrawal")
        .sign_with_relay_keys(relay)
        .expect("sign synthetic withdrawal")
}

fn raw_status_event(relay: &Keys, content: &str, issued_at: u64) -> Event {
    EventBuilder::new(
        Kind::Custom(KIND_CLIENT_BINDING_STATUS as u16),
        content.to_string(),
    )
    .tags([])
    .custom_created_at(Timestamp::from(issued_at))
    .sign_with_keys(relay)
    .expect("sign synthetic raw status")
}

async fn established_flow(
    relay: &Keys,
    author: PublicKey,
    domain: CommunityId,
    now: u64,
) -> NativeFlow {
    let epoch = random_epoch();
    let mut flow = NativeFlow::connect(relay.public_key(), author, epoch.clone()).await;
    let bootstrap = bootstrap_event(relay, domain, author, epoch, now);
    flow.send_reserved_event(CLIENT_BINDING_BOOTSTRAP_SUB_ID, &bootstrap, now)
        .await;
    let current = current_event(relay, domain, author, 1, now, now + 120);
    flow.send_reserved_event(CLIENT_BINDING_STATUS_SUB_ID, &current, now)
        .await;
    assert!(flow.projection.is_some());
    flow
}

#[tokio::test]
async fn loopback_relay_drives_production_projection_and_trace() {
    let relay = Keys::generate();
    let wrong_signer = Keys::generate();
    let author = Keys::generate();
    let other_author = Keys::generate();
    let profile_spoofer = Keys::generate();
    let domain = random_domain();
    let other_domain = random_domain();
    assert_ne!(domain, other_domain);

    let mut trace = ProjectionTrace::new();

    // One physical connection exercises the revision fold as a sequence, proving that
    // duplicate delivery retains current state while trusted-invalid evidence clears it.
    let epoch = random_epoch();
    let mut flow =
        NativeFlow::connect(relay.public_key(), author.public_key(), epoch.clone()).await;
    let bootstrap = bootstrap_event(&relay, domain, author.public_key(), epoch.clone(), NOW);
    flow.send_reserved_event(CLIENT_BINDING_BOOTSTRAP_SUB_ID, &bootstrap, NOW)
        .await;
    trace.record("bootstrap", &flow);

    let current = current_event(&relay, domain, author.public_key(), 10, NOW, NOW + 120);
    flow.send_reserved_event(CLIENT_BINDING_STATUS_SUB_ID, &current, NOW)
        .await;
    let first_projection =
        serde_json::to_value(&flow.projection).expect("serialize first production projection");
    let projected = flow.projection.as_ref().expect("current status projects");
    assert_eq!(projected.event_author_pubkey, author.public_key().to_hex());
    assert_eq!(projected.fresh_until, NOW + 120);
    assert_eq!(projected.connection_epoch, epoch.as_str());
    trace.record("current", &flow);

    flow.send_reserved_event(CLIENT_BINDING_STATUS_SUB_ID, &current, NOW)
        .await;
    assert_eq!(
        serde_json::to_value(&flow.projection).expect("serialize duplicate projection"),
        first_projection
    );
    trace.record("duplicate", &flow);

    let equal_conflict = current_event(&relay, domain, author.public_key(), 10, NOW, NOW + 121);
    flow.send_reserved_event(CLIENT_BINDING_STATUS_SUB_ID, &equal_conflict, NOW)
        .await;
    assert!(flow.projection.is_none());
    trace.record("equal-conflict", &flow);

    let rollback = current_event(&relay, domain, author.public_key(), 9, NOW, NOW + 120);
    flow.send_reserved_event(CLIENT_BINDING_STATUS_SUB_ID, &rollback, NOW)
        .await;
    assert!(flow.projection.is_none());
    trace.record("rollback", &flow);

    let newer = current_event(&relay, domain, author.public_key(), 11, NOW, NOW + 120);
    flow.send_reserved_event(CLIENT_BINDING_STATUS_SUB_ID, &newer, NOW)
        .await;
    assert!(flow.projection.is_some());
    trace.record("newer-restoration", &flow);

    let withdrawal = withdrawal_event(&relay, domain, author.public_key(), 12, NOW, NOW + 120);
    flow.send_reserved_event(CLIENT_BINDING_STATUS_SUB_ID, &withdrawal, NOW)
        .await;
    assert!(flow.projection.is_none());
    trace.record("withdrawal", &flow);

    let short_current = current_event(&relay, domain, author.public_key(), 13, NOW, NOW + 2);
    flow.send_reserved_event(CLIENT_BINDING_STATUS_SUB_ID, &short_current, NOW)
        .await;
    assert!(flow.projection.is_some());
    flow.expire(NOW + 2);
    assert!(flow.projection.is_none());
    trace.record("passive-expiry", &flow);

    let disconnect_current =
        current_event(&relay, domain, author.public_key(), 14, NOW + 3, NOW + 123);
    flow.send_reserved_event(CLIENT_BINDING_STATUS_SUB_ID, &disconnect_current, NOW + 3)
        .await;
    assert!(flow.projection.is_some());
    flow.physical_disconnect().await;
    assert!(flow.projection.is_none());
    trace.record("disconnect", &flow);

    let mut reconnected = established_flow(&relay, author.public_key(), domain, NOW + 10).await;
    trace.record("reconnect", &reconnected);
    reconnected.physical_disconnect().await;
    trace.record("logout", &reconnected);

    let mut restarted = established_flow(&relay, author.public_key(), domain, NOW + 20).await;
    restarted.physical_disconnect().await;
    trace.record("restart", &restarted);

    // A different physical relay connection starts empty even when the signer is reused.
    let relay_epoch = random_epoch();
    let relay_scope =
        NativeFlow::connect(relay.public_key(), author.public_key(), relay_epoch).await;
    trace.record("relay-scope-change", &relay_scope);

    // Wrong-signer traffic is untrusted noise and cannot create or clear presentation.
    let signer_epoch = random_epoch();
    let mut signer_scope = NativeFlow::connect(
        wrong_signer.public_key(),
        author.public_key(),
        signer_epoch.clone(),
    )
    .await;
    let old_signer_bootstrap =
        bootstrap_event(&relay, domain, author.public_key(), signer_epoch, NOW + 30);
    signer_scope
        .send_reserved_event(
            CLIENT_BINDING_BOOTSTRAP_SUB_ID,
            &old_signer_bootstrap,
            NOW + 30,
        )
        .await;
    trace.record("signer-scope-change", &signer_scope);

    let author_epoch = random_epoch();
    let mut author_scope = NativeFlow::connect(
        relay.public_key(),
        other_author.public_key(),
        author_epoch.clone(),
    )
    .await;
    let old_author_bootstrap =
        bootstrap_event(&relay, domain, author.public_key(), author_epoch, NOW + 31);
    author_scope
        .send_reserved_event(
            CLIENT_BINDING_BOOTSTRAP_SUB_ID,
            &old_author_bootstrap,
            NOW + 31,
        )
        .await;
    trace.record("author-scope-change", &author_scope);

    let domain_epoch = random_epoch();
    let mut domain_scope = NativeFlow::connect(
        relay.public_key(),
        author.public_key(),
        domain_epoch.clone(),
    )
    .await;
    let domain_bootstrap = bootstrap_event(
        &relay,
        other_domain,
        author.public_key(),
        domain_epoch,
        NOW + 32,
    );
    domain_scope
        .send_reserved_event(CLIENT_BINDING_BOOTSTRAP_SUB_ID, &domain_bootstrap, NOW + 32)
        .await;
    let old_domain_status =
        current_event(&relay, domain, author.public_key(), 1, NOW + 32, NOW + 152);
    domain_scope
        .send_reserved_event(CLIENT_BINDING_STATUS_SUB_ID, &old_domain_status, NOW + 32)
        .await;
    trace.record("domain-scope-change", &domain_scope);

    let old_epoch = random_epoch();
    let new_epoch = random_epoch();
    assert_ne!(old_epoch, new_epoch);
    let mut epoch_scope =
        NativeFlow::connect(relay.public_key(), author.public_key(), new_epoch).await;
    let stale_epoch_bootstrap =
        bootstrap_event(&relay, domain, author.public_key(), old_epoch, NOW + 33);
    epoch_scope
        .send_reserved_event(
            CLIENT_BINDING_BOOTSTRAP_SUB_ID,
            &stale_epoch_bootstrap,
            NOW + 33,
        )
        .await;
    trace.record("epoch-scope-change", &epoch_scope);

    let mut malformed = established_flow(&relay, author.public_key(), domain, NOW + 40).await;
    let malformed_status = raw_status_event(&relay, r#"{"version":1,"domain":"broken"}"#, NOW + 40);
    malformed
        .send_reserved_event(CLIENT_BINDING_STATUS_SUB_ID, &malformed_status, NOW + 40)
        .await;
    trace.record("malformed-trusted", &malformed);

    let mut unsupported = established_flow(&relay, author.public_key(), domain, NOW + 41).await;
    let unsupported_status = raw_status_event(&relay, r#"{"version":2}"#, NOW + 41);
    unsupported
        .send_reserved_event(CLIENT_BINDING_STATUS_SUB_ID, &unsupported_status, NOW + 41)
        .await;
    trace.record("unsupported-version", &unsupported);

    let mut mismatched_author =
        established_flow(&relay, author.public_key(), domain, NOW + 42).await;
    let author_mismatch = current_event(
        &relay,
        domain,
        other_author.public_key(),
        2,
        NOW + 42,
        NOW + 162,
    );
    mismatched_author
        .send_reserved_event(CLIENT_BINDING_STATUS_SUB_ID, &author_mismatch, NOW + 42)
        .await;
    trace.record("author-mismatch", &mismatched_author);

    // Ordinary kind-0 and NIP-85 traffic crosses the same socket but never enters the
    // reserved production fold, so neither can manufacture a current projection.
    let mut legacy =
        NativeFlow::connect(relay.public_key(), author.public_key(), random_epoch()).await;
    let spoofed_profile = EventBuilder::new(
        Kind::Metadata,
        r#"{"display_name":"Spoofed Verified User","nip05":"spoof@identity.example.invalid"}"#,
    )
    .sign_with_keys(&profile_spoofer)
    .expect("sign synthetic profile spoof");
    legacy.send_ordinary_event(&spoofed_profile, NOW + 50).await;
    trace.record("profile-spoof", &legacy);

    let subject = author.public_key().to_hex();
    let expiry = (NOW + 170).to_string();
    let nip85 = EventBuilder::new(
        Kind::Custom(KIND_USER_TRUSTED_ASSERTION as u16),
        String::new(),
    )
    .tags([
        Tag::parse(["d", subject.as_str()]).expect("synthetic d tag"),
        Tag::parse(["p", subject.as_str()]).expect("synthetic p tag"),
        Tag::parse(["verified", "relay"]).expect("synthetic verified tag"),
        Tag::parse(["active", "true"]).expect("synthetic active tag"),
        Tag::parse(["expiration", expiry.as_str()]).expect("synthetic expiration tag"),
        Tag::parse(["display_name", "Spoofed Legacy Assertion"])
            .expect("synthetic display-name tag"),
    ])
    .sign_with_keys(&relay)
    .expect("sign synthetic NIP-85 assertion");
    legacy.send_ordinary_event(&nip85, NOW + 50).await;
    trace.record("nip85-no-fallback", &legacy);

    let cases = trace.steps.iter().map(|step| step.case).collect::<Vec<_>>();
    assert_eq!(
        cases,
        [
            "bootstrap",
            "current",
            "duplicate",
            "equal-conflict",
            "rollback",
            "newer-restoration",
            "withdrawal",
            "passive-expiry",
            "disconnect",
            "reconnect",
            "logout",
            "restart",
            "relay-scope-change",
            "signer-scope-change",
            "author-scope-change",
            "domain-scope-change",
            "epoch-scope-change",
            "malformed-trusted",
            "unsupported-version",
            "author-mismatch",
            "profile-spoof",
            "nip85-no-fallback",
        ]
    );
    for step in &trace.steps {
        let expected_current = matches!(
            step.case,
            "current" | "duplicate" | "newer-restoration" | "reconnect"
        );
        assert_eq!(
            step.projection.is_some(),
            expected_current,
            "unexpected retained projection for {}",
            step.case
        );
    }

    trace.assert_contract_and_export_if_requested();
}
