//! Test-only J3C relay-authenticated client-binding status composition.
//!
//! This harness deliberately composes only public production contracts. It
//! binds a real loopback WebSocket, creates verification-only evidence through
//! the authorization finalizer, asks the production issuer and exact-connection
//! transport to deliver, frames that issuer-produced event with the production
//! relay serializer, and folds it with the production client tracker.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use buzz_auth::evidence_adapter::{ActiveBindingResolution, VerifiedEvidenceAdapter};
use buzz_auth::{
    resolve_authorization, resolve_current_federated_policy, ApplicationLeaseLimit,
    AssertionTransport, AuthContextInput, AuthTransport, AuthorityAdapterError,
    AuthorityAdapterFuture, AuthorizationCapability, AuthorizationClock, AuthorizationClockError,
    AuthorizationClockSkew, AuthorizationFinalizer, AuthorizationOutcome, AuthorizationProfileId,
    AuthorizationProvider, AuthorizationProviderFuture, AuthorizationRequest, AuthorizationTime,
    AuthorizedCommunityAccess, BindingExpiry, BindingLeaseBound, BindingResolutionRequest,
    BindingSource, BindingVersion, CapabilitySet, CurrentPolicyRequest,
    CurrentPolicyResolutionSink, DirectBindingResolutionSink, EnrollmentMode,
    ExistingBindingResolutionSink, FederatedAuthorityAdapter, FederatedAuthorization,
    FederatedIdentityRequirement, PolicyVersion, ProviderAllow, ProviderAuthorizationClock,
    ProviderDecision, ProviderTimeout, Scope, VerificationOnlyDisposition,
    VerificationStatusPolicy,
};
use buzz_core::client_binding_status::{
    ClientBindingStatusError, ClientBindingStatusFoldError, ClientBindingStatusInputV1,
    ClientBindingStatusTracker, ClientBindingStatusUpdate,
};
use buzz_core::kind::{KIND_CLIENT_BINDING_STATUS, KIND_USER_TRUSTED_ASSERTION};
use buzz_core::CommunityId;
use buzz_relay::authorization_runtime::status::{
    AuthoritativeClientStatusEvidence, ClientStatusPresentationGateError,
    ClientStatusPresentationPermit, ClientStatusPrivacyKey, ClientStatusRevisionScope,
    CompleteClientStatusPresentationApproval, ConnectionManagerClientStatusTransport,
    DurableClientStatusRevision, DurableClientStatusRevisionSource, ProviderNeutralPolicyRevision,
    RelayClientBindingStatusIssuer,
};
use buzz_relay::connection::OutboundData;
use buzz_relay::protocol::RelayMessage;
use buzz_relay::state::ConnectionManager;
use futures::{SinkExt, StreamExt};
use nostr::{Event, EventBuilder, JsonUtil, Keys, Kind, RelayUrl, Timestamp};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const STATUS_SUBSCRIPTION: &str = "__buzz_client_binding_status_v1__";

#[derive(Clone)]
struct FixedClock(u64);

impl AuthorizationClock for FixedClock {
    fn now(&self) -> Result<AuthorizationTime, AuthorizationClockError> {
        Ok(AuthorizationTime::from_unix_seconds(self.0))
    }
}

impl ProviderAuthorizationClock for FixedClock {
    fn now_unix_seconds(&self) -> Option<u64> {
        Some(self.0)
    }
}

struct SyntheticAuthority {
    policy_id: Uuid,
    binding_id: Uuid,
    binding_version: BindingVersion,
    valid_until: u64,
}

impl SyntheticAuthority {
    fn resolve_binding(
        &self,
        request: BindingResolutionRequest,
        sink: DirectBindingResolutionSink,
    ) -> Result<buzz_auth::context::AuthoritativeBindingResolution, AuthorityAdapterError<Infallible>>
    {
        Ok(sink.existing_active(
            request.authorization_domain(),
            self.binding_id,
            request.principal().clone(),
            request.bound_pubkey(),
            self.binding_version,
            Some(BindingExpiry::new(self.valid_until)?),
            BindingSource::AttestedKey,
        )?)
    }
}

impl FederatedAuthorityAdapter for SyntheticAuthority {
    type Error = Infallible;

    fn resolve_current_policy<'a>(
        &'a self,
        request: CurrentPolicyRequest,
        sink: CurrentPolicyResolutionSink,
    ) -> AuthorityAdapterFuture<
        'a,
        Result<buzz_auth::ResolvedFederatedPolicy, AuthorityAdapterError<Self::Error>>,
    > {
        Box::pin(async move {
            Ok(sink.resolved(
                request.authorization_domain(),
                self.policy_id,
                1,
                FederatedIdentityRequirement::Required(EnrollmentMode::AttestedKey),
                request.observed_at().saturating_sub(1),
                self.valid_until,
            )?)
        })
    }

    fn resolve_direct_binding<'a>(
        &'a self,
        request: BindingResolutionRequest,
        sink: DirectBindingResolutionSink,
    ) -> AuthorityAdapterFuture<
        'a,
        Result<
            buzz_auth::context::AuthoritativeBindingResolution,
            AuthorityAdapterError<Self::Error>,
        >,
    > {
        Box::pin(async move { self.resolve_binding(request, sink) })
    }

    fn resolve_existing_binding<'a>(
        &'a self,
        request: BindingResolutionRequest,
        sink: ExistingBindingResolutionSink,
    ) -> AuthorityAdapterFuture<
        'a,
        Result<
            buzz_auth::context::AuthoritativeBindingResolution,
            AuthorityAdapterError<Self::Error>,
        >,
    > {
        Box::pin(async move {
            Ok(sink.existing_active(
                request.authorization_domain(),
                self.binding_id,
                request.principal().clone(),
                request.bound_pubkey(),
                self.binding_version,
                Some(BindingExpiry::new(self.valid_until)?),
                BindingSource::AttestedKey,
            )?)
        })
    }
}

struct SyntheticProvider {
    profile: AuthorizationProfileId,
    policy: PolicyVersion,
    issued_at: u64,
    fresh_until: u64,
}

impl AuthorizationProvider for SyntheticProvider {
    fn profile_id(&self) -> AuthorizationProfileId {
        self.profile.clone()
    }

    fn authorize<'a>(
        &'a self,
        request: &'a AuthorizationRequest,
    ) -> AuthorizationProviderFuture<'a> {
        let decision = ProviderAllow::new(
            request.authorization_domain(),
            request.principal().clone(),
            self.profile.clone(),
            request.requested_capabilities().clone(),
            self.policy.clone(),
            self.issued_at,
            self.fresh_until,
        )
        .expect("synthetic provider output must satisfy the production contract");
        Box::pin(std::future::ready(ProviderDecision::Allow(decision)))
    }
}

struct CompleteSyntheticApproval {
    reviewed_revision: String,
}

impl CompleteClientStatusPresentationApproval for CompleteSyntheticApproval {
    fn reviewed_implementation_revision(&self) -> &str {
        &self.reviewed_revision
    }

    fn presentation_gate_passed(&self) -> bool {
        true
    }

    fn dedicated_client_contract_passed(&self) -> bool {
        true
    }
}

struct SyntheticRevisions {
    revision: AtomicU64,
    current_reads: AtomicUsize,
    withdrawal_reads: AtomicUsize,
    scopes: Mutex<Vec<ClientStatusRevisionScope>>,
}

impl SyntheticRevisions {
    fn new(revision: u64) -> Self {
        Self {
            revision: AtomicU64::new(revision),
            current_reads: AtomicUsize::new(0),
            withdrawal_reads: AtomicUsize::new(0),
            scopes: Mutex::new(Vec::new()),
        }
    }

    fn set(&self, revision: u64) {
        self.revision.store(revision, Ordering::SeqCst);
    }

    fn durable(&self) -> Option<DurableClientStatusRevision> {
        let revision = self.revision.load(Ordering::SeqCst);
        DurableClientStatusRevision::from_durable_state(revision, revision).ok()
    }
}

#[async_trait]
impl DurableClientStatusRevisionSource for SyntheticRevisions {
    async fn current_revision_for(
        &self,
        requirement: &buzz_relay::authorization_runtime::status::ClientStatusCurrentRequirement<'_>,
        _issuance_fingerprint: [u8; 32],
    ) -> Option<DurableClientStatusRevision> {
        self.current_reads.fetch_add(1, Ordering::SeqCst);
        self.scopes
            .lock()
            .expect("synthetic revision scope lock")
            .push(requirement.scope());
        self.durable()
    }

    async fn withdrawal_revision_for(
        &self,
        receipt: &buzz_relay::authorization_runtime::status::ClientStatusIssuanceReceipt,
        _withdrawal_fingerprint: [u8; 32],
    ) -> Option<DurableClientStatusRevision> {
        self.withdrawal_reads.fetch_add(1, Ordering::SeqCst);
        assert!(!receipt.connection_id().is_nil());
        self.durable()
    }
}

async fn verification_only_disposition(
    relay_url: &str,
    domain: CommunityId,
    author: &Keys,
    now: u64,
) -> (VerificationOnlyDisposition, ClientStatusPrivacyKey) {
    let adapter = VerifiedEvidenceAdapter::new();
    let challenge = Uuid::new_v4().to_string();
    let auth_event = EventBuilder::auth(
        challenge.clone(),
        RelayUrl::parse(relay_url).expect("loopback relay URL is valid"),
    )
    .sign_with_keys(author)
    .expect("ephemeral author signs NIP-42 proof");
    let proof = adapter
        .verify_nip42(
            domain,
            AuthTransport::RelayWebSocket,
            &auth_event,
            &challenge,
            relay_url,
            None,
        )
        .expect("production verifier seals the loopback NIP-42 proof");

    let issuer = format!("https://{}.invalid", Uuid::new_v4());
    let subject = Uuid::new_v4().to_string();
    let assertion = adapter
        .federated_assertion_from_validated_claims(
            domain,
            AuthTransport::RelayWebSocket,
            &issuer,
            &subject,
            Some(author.public_key()),
            AssertionTransport::TrustedProxy,
            Some(now.saturating_sub(1)),
            now + 240,
            now,
        )
        .expect("synthetic validated claims seal exact assertion evidence");
    let correlation_id = Uuid::new_v4();
    let authority = SyntheticAuthority {
        policy_id: Uuid::new_v4(),
        binding_id: Uuid::new_v4(),
        binding_version: BindingVersion::new(7).expect("positive synthetic binding version"),
        valid_until: now + 240,
    };
    let policy = resolve_current_federated_policy(&authority, domain, correlation_id, now)
        .await
        .expect("test-only authoritative policy resolves");
    let profile = AuthorizationProfileId::from_server_configuration(format!(
        "synthetic-profile-{}",
        Uuid::new_v4()
    ))
    .expect("synthetic profile is valid");
    let provider_policy = PolicyVersion::new(format!("private-policy-{}", Uuid::new_v4()))
        .expect("synthetic provider policy is valid");
    let capabilities = CapabilitySet::single(AuthorizationCapability::CommunityRead);
    let request = AuthorizationRequest::direct(
        &proof,
        &assertion,
        policy,
        capabilities,
        correlation_id,
        now,
    )
    .expect("exact direct provider request is valid");
    let provider = SyntheticProvider {
        profile: profile.clone(),
        policy: provider_policy,
        issued_at: now,
        fresh_until: now + 180,
    };
    let snapshot = match resolve_authorization(
        &provider,
        &request,
        &FixedClock(now),
        ProviderTimeout::new(Duration::from_secs(1)).expect("bounded provider timeout"),
        Uuid::new_v4(),
    )
    .await
    {
        AuthorizationOutcome::Allow(snapshot) => snapshot,
        other => panic!("synthetic exact provider request must allow: {other:?}"),
    };
    let binding = adapter
        .active_binding_from_store(
            domain,
            domain,
            authority.binding_id,
            &issuer,
            &subject,
            author.public_key(),
            authority.binding_version.get(),
            Some(authority.valid_until),
            BindingSource::AttestedKey,
            ActiveBindingResolution::Existing,
            Some(&assertion),
        )
        .expect("typed current binding store output seals");
    let binding_bound = BindingLeaseBound::new(&binding, authority.valid_until)
        .expect("synthetic binding bound is current");
    let tenant =
        buzz_core::tenant::TenantContext::resolved(domain, format!("{}.invalid", Uuid::new_v4()));
    let admission: AuthorizedCommunityAccess = adapter
        .community_access_from_policy(&tenant, domain, vec![Scope::MessagesRead], None)
        .expect("server-resolved community admission seals");
    let input = AuthContextInput::new(tenant, correlation_id, proof, admission);
    let policy = resolve_current_federated_policy(&authority, domain, correlation_id, now)
        .await
        .expect("same current policy resolves at finalization");
    let finalizer = AuthorizationFinalizer::new(Arc::new(FixedClock(now)));
    let disposition = finalizer
        .finalize_verification_only(
            input,
            policy,
            FederatedAuthorization::Direct { binding, assertion },
            snapshot,
            &profile,
            binding_bound,
            VerificationStatusPolicy::new(
                ApplicationLeaseLimit::from_seconds(120).expect("short display lifetime is valid"),
                AuthorizationClockSkew::from_seconds(0).expect("zero skew is valid"),
            ),
        )
        .expect("production finalizer yields display-only evidence");
    let privacy_key = ClientStatusPrivacyKey::from_secret(rand::random());
    (disposition, privacy_key)
}

fn register_authenticated_connection(
    connections: &ConnectionManager,
    connection_id: Uuid,
    domain: CommunityId,
    author: &Keys,
) -> (
    mpsc::Receiver<OutboundData>,
    mpsc::Receiver<axum::extract::ws::Message>,
) {
    let (tx, rx) = mpsc::channel(16);
    let (ctrl_tx, ctrl_rx) = mpsc::channel(4);
    connections.register(
        connection_id,
        tx,
        ctrl_tx,
        CancellationToken::new(),
        domain,
        Arc::new(AtomicU8::new(0)),
        Arc::new(AsyncMutex::new(HashMap::new())),
        3,
    );
    connections.set_authenticated_pubkey(connection_id, author.public_key().to_bytes().to_vec());
    (rx, ctrl_rx)
}

fn authoritative_evidence(
    disposition: &VerificationOnlyDisposition,
    privacy_key: &ClientStatusPrivacyKey,
) -> AuthoritativeClientStatusEvidence {
    let policy_revision = ProviderNeutralPolicyRevision::derive(
        privacy_key,
        disposition.profile_id(),
        disposition.policy_version(),
    )
    .expect("ephemeral privacy key derives provider-neutral policy revision");
    AuthoritativeClientStatusEvidence::from_authoritative_runtime(
        disposition.authorization_domain(),
        disposition.actor_pubkey(),
        disposition.binding_id(),
        disposition.binding_version(),
        disposition.profile_id().clone(),
        disposition.policy_version().clone(),
        policy_revision,
        disposition.correlation_id(),
        1,
        disposition.issued_at(),
        disposition.expires_at(),
    )
}

fn raw_signed_event(keys: &Keys, kind: u32, content: String, issued_at: u64) -> Event {
    EventBuilder::new(Kind::Custom(kind as u16), content)
        .custom_created_at(Timestamp::from(issued_at))
        .sign_with_keys(keys)
        .expect("ephemeral synthetic event signs")
}

async fn receive_status(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Event {
    let message = timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("loopback status frame must not time out")
        .expect("loopback relay remains connected")
        .expect("loopback WebSocket frame is valid");
    let Message::Text(text) = message else {
        panic!("client status must use a text WebSocket frame");
    };
    let envelope: Value = serde_json::from_str(&text).expect("relay frame is JSON");
    assert_eq!(envelope[0], "EVENT");
    assert_eq!(envelope[1], STATUS_SUBSCRIPTION);
    Event::from_json(envelope[2].to_string()).expect("relay frame carries a Nostr event")
}

async fn round_trip(
    sender: &mpsc::UnboundedSender<String>,
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    event: &Event,
) -> Event {
    sender
        .send(RelayMessage::event(STATUS_SUBSCRIPTION, event))
        .expect("loopback relay task remains live");
    let received = receive_status(socket).await;
    assert_eq!(received.id, event.id, "wire event must be issuer-produced");
    received
}

#[tokio::test]
async fn relay_authenticated_status_uses_real_loopback_and_exact_connection_scope() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral loopback listener binds");
    let address = listener
        .local_addr()
        .expect("loopback listener has an address");
    assert_ne!(address.port(), 0, "OS must allocate a real ephemeral port");
    let relay_url = format!("ws://{address}");
    let (frame_tx, mut frame_rx) = mpsc::unbounded_channel::<String>();
    let server = tokio::spawn(async move {
        let (tcp, peer) = listener.accept().await.expect("loopback client connects");
        assert!(peer.ip().is_loopback(), "harness must remain loopback-only");
        let mut websocket = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("loopback WebSocket upgrades");
        let mut sent = 0usize;
        while let Some(frame) = frame_rx.recv().await {
            websocket
                .send(Message::Text(frame.into()))
                .await
                .expect("loopback status frame sends");
            sent += 1;
        }
        let _ = websocket.close(None).await;
        sent
    });
    let (mut socket, _) = tokio_tungstenite::connect_async(&relay_url)
        .await
        .expect("real loopback WebSocket client connects");

    let now = Timestamp::now().as_secs();
    let relay = Keys::generate();
    let author = Keys::generate();
    let spoof = Keys::generate();
    let wrong_relay = Keys::generate();
    let domain = CommunityId::from_uuid(Uuid::new_v4());
    let wrong_domain = CommunityId::from_uuid(Uuid::new_v4());
    let connection_id = Uuid::new_v4();
    let (disposition, privacy_key) =
        verification_only_disposition(&relay_url, domain, &author, now).await;
    let evidence = authoritative_evidence(&disposition, &privacy_key);
    let revisions = SyntheticRevisions::new(10);
    let issuer = RelayClientBindingStatusIssuer::new(&relay, &revisions, &privacy_key);
    let permit = ClientStatusPresentationPermit::from_complete_stack(&CompleteSyntheticApproval {
        reviewed_revision: "a".repeat(40),
    })
    .expect("test-only complete approval constructs the production gate");

    let connections = Arc::new(ConnectionManager::new());
    let (_outbound_rx, _ctrl_rx) =
        register_authenticated_connection(&connections, connection_id, domain, &author);
    let transport = ConnectionManagerClientStatusTransport::new(Arc::clone(&connections));
    let current_attempt = issuer
        .deliver_verification_only(&permit, &disposition, 1, None, connection_id, &transport)
        .await
        .expect("production issuer creates current status");
    assert_eq!(current_attempt.delivery_error(), None);
    assert_eq!(current_attempt.receipt().connection_id(), connection_id);
    assert_eq!(current_attempt.receipt().revision(), 10);
    assert_eq!(current_attempt.event().pubkey, relay.public_key());
    assert!(current_attempt.event().verify().is_ok());
    assert!(!current_attempt
        .event()
        .content
        .contains(disposition.profile_id().as_str()));
    assert!(!current_attempt
        .event()
        .content
        .contains(disposition.policy_version().as_str()));

    // The same issuer cannot target a connection authenticated as another key
    // or resolved for another authorization domain.
    let wrong_author_connection = Uuid::new_v4();
    let (_wrong_author_rx, _wrong_author_ctrl_rx) =
        register_authenticated_connection(&connections, wrong_author_connection, domain, &spoof);
    let wrong_author_attempt = issuer
        .deliver_verification_only(
            &permit,
            &disposition,
            1,
            None,
            wrong_author_connection,
            &transport,
        )
        .await
        .expect("issuance succeeds independently of exact delivery");
    assert!(wrong_author_attempt.delivery_error().is_some());

    let wrong_domain_connection = Uuid::new_v4();
    let (_wrong_domain_rx, _wrong_domain_ctrl_rx) = register_authenticated_connection(
        &connections,
        wrong_domain_connection,
        wrong_domain,
        &author,
    );
    let wrong_domain_attempt = issuer
        .deliver_verification_only(
            &permit,
            &disposition,
            1,
            None,
            wrong_domain_connection,
            &transport,
        )
        .await
        .expect("issuance succeeds independently of exact delivery");
    assert!(wrong_domain_attempt.delivery_error().is_some());

    revisions.set(10);
    let current = round_trip(&frame_tx, &mut socket, current_attempt.event()).await;
    let mut tracker =
        ClientBindingStatusTracker::new(relay.public_key(), domain, author.public_key());
    assert_eq!(
        tracker.accept(&current, now),
        Ok(ClientBindingStatusUpdate::Accepted)
    );
    assert!(tracker.current_presentation(now).is_some());
    assert_eq!(tracker.high_water_revision(), Some(10));

    let malformed = raw_signed_event(&relay, KIND_CLIENT_BINDING_STATUS, "{".to_string(), now);
    let malformed = round_trip(&frame_tx, &mut socket, &malformed).await;
    assert_eq!(
        tracker.accept(&malformed, now),
        Err(ClientBindingStatusFoldError::InvalidStatus(
            ClientBindingStatusError::MalformedPayload
        ))
    );

    let mut unsupported_content: Value =
        serde_json::from_str(&current.content).expect("current status content is JSON");
    unsupported_content["version"] = json!(2);
    let unsupported = raw_signed_event(
        &relay,
        KIND_CLIENT_BINDING_STATUS,
        unsupported_content.to_string(),
        now,
    );
    let unsupported = round_trip(&frame_tx, &mut socket, &unsupported).await;
    assert_eq!(
        tracker.accept(&unsupported, now),
        Err(ClientBindingStatusFoldError::InvalidStatus(
            ClientBindingStatusError::UnsupportedVersion
        ))
    );

    let wrong_signer = ClientBindingStatusInputV1::current(
        domain,
        author.public_key(),
        7,
        "opaque-wrong-relay",
        11,
        now,
        now + 120,
        None,
    )
    .expect("bounded wrong-relay status input")
    .sign_with_relay_keys(&wrong_relay)
    .expect("wrong relay still produces an authenticated Nostr event");
    let wrong_signer = round_trip(&frame_tx, &mut socket, &wrong_signer).await;
    assert_eq!(
        tracker.accept(&wrong_signer, now),
        Err(ClientBindingStatusFoldError::InvalidStatus(
            ClientBindingStatusError::UnexpectedRelay
        ))
    );

    let author_mismatch = ClientBindingStatusInputV1::current(
        domain,
        spoof.public_key(),
        7,
        "opaque-author-spoof",
        11,
        now,
        now + 120,
        None,
    )
    .expect("bounded mismatched-author status input")
    .sign_with_relay_keys(&relay)
    .expect("relay signs explicit mismatched-author test event");
    let author_mismatch = round_trip(&frame_tx, &mut socket, &author_mismatch).await;
    assert_eq!(
        tracker.accept(&author_mismatch, now),
        Err(ClientBindingStatusFoldError::InvalidStatus(
            ClientBindingStatusError::EventAuthorMismatch
        ))
    );

    let domain_mismatch = ClientBindingStatusInputV1::current(
        wrong_domain,
        author.public_key(),
        7,
        "opaque-domain-spoof",
        11,
        now,
        now + 120,
        None,
    )
    .expect("bounded mismatched-domain status input")
    .sign_with_relay_keys(&relay)
    .expect("relay signs explicit mismatched-domain test event");
    let domain_mismatch = round_trip(&frame_tx, &mut socket, &domain_mismatch).await;
    assert_eq!(
        tracker.accept(&domain_mismatch, now),
        Err(ClientBindingStatusFoldError::InvalidStatus(
            ClientBindingStatusError::AuthorizationDomainMismatch
        ))
    );

    // Neither mutable profile metadata nor a legacy NIP-85 assertion can
    // restore or rename the relay-authenticated status presentation.
    for legacy in [
        raw_signed_event(
            &spoof,
            Kind::Metadata.as_u16() as u32,
            json!({"name": format!("spoof-{}", Uuid::new_v4())}).to_string(),
            now,
        ),
        raw_signed_event(
            &relay,
            KIND_USER_TRUSTED_ASSERTION,
            json!({"active": true, "label": format!("legacy-{}", Uuid::new_v4())}).to_string(),
            now,
        ),
    ] {
        let legacy = round_trip(&frame_tx, &mut socket, &legacy).await;
        assert_eq!(
            tracker.accept(&legacy, now),
            Err(ClientBindingStatusFoldError::InvalidStatus(
                ClientBindingStatusError::WrongKind
            ))
        );
        assert_eq!(tracker.high_water_revision(), Some(10));
        assert_eq!(
            tracker
                .current_presentation(now)
                .and_then(|status| status.display_label()),
            None
        );
    }

    revisions.set(11);
    let withdrawal = issuer
        .deliver_withdrawn_after_invalidation(
            &permit,
            &evidence,
            current_attempt.receipt(),
            &transport,
        )
        .await
        .expect("production issuer delivers a strictly newer withdrawal");
    let withdrawal = round_trip(&frame_tx, &mut socket, &withdrawal).await;
    assert_eq!(
        tracker.accept(&withdrawal, now),
        Ok(ClientBindingStatusUpdate::Accepted)
    );
    assert!(tracker.current_presentation(now).is_none());
    assert_eq!(
        tracker.accept(&withdrawal, now),
        Ok(ClientBindingStatusUpdate::Duplicate)
    );
    assert_eq!(
        tracker.accept(&current, now),
        Err(ClientBindingStatusFoldError::LowerRevisionReplay)
    );

    let equal_conflict = ClientBindingStatusInputV1::current(
        domain,
        author.public_key(),
        8,
        "opaque-equal-conflict",
        11,
        now,
        now + 120,
        None,
    )
    .expect("equal-revision conflict input is structurally valid")
    .sign_with_relay_keys(&relay)
    .expect("relay signs explicit conflict event");
    let equal_conflict = round_trip(&frame_tx, &mut socket, &equal_conflict).await;
    assert_eq!(
        tracker.accept(&equal_conflict, now),
        Err(ClientBindingStatusFoldError::ConflictingEqualRevision)
    );

    revisions.set(12);
    let restored_attempt = issuer
        .deliver_verification_only(&permit, &disposition, 1, None, connection_id, &transport)
        .await
        .expect("production issuer creates strictly newer restoration");
    assert_eq!(restored_attempt.delivery_error(), None);
    let restored = round_trip(&frame_tx, &mut socket, restored_attempt.event()).await;
    assert_eq!(
        tracker.accept(&restored, now),
        Ok(ClientBindingStatusUpdate::Accepted)
    );
    assert!(tracker.current_presentation(now).is_some());

    tracker.on_disconnect();
    assert!(tracker.current_presentation(now).is_none());
    assert_eq!(tracker.high_water_revision(), Some(12));
    assert_eq!(
        tracker.accept(&restored, now),
        Ok(ClientBindingStatusUpdate::Duplicate),
        "reconnect must not restore presentation from a duplicate"
    );
    assert!(tracker.current_presentation(now).is_none());

    revisions.set(13);
    let reconnect_attempt = issuer
        .deliver_verification_only(&permit, &disposition, 2, None, connection_id, &transport)
        .await
        .expect("reconnect obtains a newer production issuance");
    let reconnect = round_trip(&frame_tx, &mut socket, reconnect_attempt.event()).await;
    assert_eq!(
        tracker.accept(&reconnect, now),
        Ok(ClientBindingStatusUpdate::Accepted)
    );
    assert!(tracker.current_presentation(now).is_some());
    assert!(tracker
        .current_presentation(disposition.expires_at())
        .is_none());
    assert_eq!(tracker.high_water_revision(), Some(13));

    tracker.change_scope(relay.public_key(), wrong_domain, author.public_key());
    assert_eq!(tracker.high_water_revision(), None);
    assert!(tracker.current_presentation(now).is_none());
    assert_eq!(
        tracker.accept(&reconnect, now),
        Err(ClientBindingStatusFoldError::InvalidStatus(
            ClientBindingStatusError::AuthorizationDomainMismatch
        ))
    );

    // Logout/restart starts with no projection. It does not synthesize a
    // profile-derived or NIP-85-derived fallback while awaiting a new status.
    let mut restarted =
        ClientBindingStatusTracker::new(relay.public_key(), domain, author.public_key());
    assert!(restarted.current_presentation(now).is_none());
    assert_eq!(restarted.high_water_revision(), None);

    assert_eq!(revisions.current_reads.load(Ordering::SeqCst), 5);
    assert_eq!(revisions.withdrawal_reads.load(Ordering::SeqCst), 1);
    let observed_scopes = revisions
        .scopes
        .lock()
        .expect("synthetic revision scope lock");
    assert!(
        !observed_scopes.is_empty(),
        "issuer must read durable scope"
    );
    assert!(observed_scopes.iter().all(|scope| {
        scope.authorization_domain() == domain && scope.event_author_pubkey() == author.public_key()
    }));
    drop(observed_scopes);

    drop(frame_tx);
    let sent = server.await.expect("loopback relay task exits cleanly");
    assert!(
        sent >= 12,
        "non-vacuity: all status cases crossed WebSocket"
    );
}

#[test]
fn composition_is_test_only_and_stock_production_remains_unwired() {
    const HARNESS: &str = include_str!("j3c_current_binding_relay_harness.rs");
    const MAIN: &str = include_str!("../src/main.rs");
    const LIB: &str = include_str!("../src/lib.rs");
    const ROUTER: &str = include_str!("../src/router.rs");
    const STATE: &str = include_str!("../src/state.rs");

    assert!(file!().contains("/tests/") || file!().starts_with("tests/"));
    for required in [
        "TcpListener::bind(\"127.0.0.1:0\")",
        "RelayClientBindingStatusIssuer::new",
        "ConnectionManagerClientStatusTransport::new",
        "ClientBindingStatusTracker::new",
        "RelayMessage::event",
    ] {
        assert!(
            HARNESS.contains(required),
            "missing non-vacuity seam: {required}"
        );
    }
    for production_root in [MAIN, LIB, ROUTER, STATE] {
        assert!(!production_root.contains("CompleteSyntheticApproval"));
        assert!(!production_root.contains("SyntheticRevisions"));
        assert!(!production_root.contains("j3c_current_binding_relay_harness"));
        assert!(!production_root.contains("ProductionClientStatusRuntime::new"));
        assert!(!production_root.contains("ClientStatusPresentationPermit::from_complete_stack"));
    }

    let incomplete = CompleteSyntheticApproval {
        reviewed_revision: "not-a-revision".to_string(),
    };
    assert!(matches!(
        ClientStatusPresentationPermit::from_complete_stack(&incomplete),
        Err(ClientStatusPresentationGateError::Incomplete)
    ));
}
