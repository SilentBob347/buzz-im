//! Relay-authenticated connection bootstrap for client binding status.
//!
//! Kind `24245` is delivered only on the WebSocket connection whose native
//! client supplied the echoed epoch. It binds the relay's NIP-11 signing key,
//! the server-resolved authorization domain, and the authenticated event
//! author before kind `24244` status can be consumed.

use std::fmt;

use nostr::{Event, EventBuilder, Keys, Kind, PublicKey, Timestamp};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{kind::KIND_CLIENT_BINDING_BOOTSTRAP, verify_event, CommunityId};

/// WebSocket upgrade header carrying a native-generated connection epoch.
pub const CLIENT_BINDING_EPOCH_HEADER: &str = "x-buzz-client-binding-epoch-v1";
/// Reserved exact-connection subscription id for bootstrap delivery.
pub const CLIENT_BINDING_BOOTSTRAP_SUB_ID: &str = "__buzz_client_binding_bootstrap_v1__";
/// Reserved exact-connection subscription id for status delivery.
pub const CLIENT_BINDING_STATUS_SUB_ID: &str = "__buzz_client_binding_status_v1__";
/// Bootstrap wire version accepted by this module.
pub const CLIENT_BINDING_BOOTSTRAP_VERSION: u64 = 1;
/// Maximum encoded bootstrap payload length.
pub const MAX_CLIENT_BINDING_BOOTSTRAP_PAYLOAD_BYTES: usize = 1024;

/// Opaque, native-generated 256-bit connection epoch.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClientBindingEpoch(String);

impl ClientBindingEpoch {
    /// Construct an epoch from 32 CSPRNG bytes.
    pub fn from_random_bytes(bytes: [u8; 32]) -> Self {
        Self(hex::encode(bytes))
    }

    /// Parse the canonical 64-character lowercase hexadecimal wire form.
    pub fn parse(value: &str) -> Result<Self, ClientBindingBootstrapError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ClientBindingBootstrapError::InvalidConnectionEpoch);
        }
        Ok(Self(value.to_owned()))
    }

    /// Canonical header and payload representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ClientBindingEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ClientBindingEpoch")
            .field(&"[redacted]")
            .finish()
    }
}

/// Validated relay-authenticated bootstrap.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientBindingBootstrapV1 {
    authorization_domain: CommunityId,
    event_author_pubkey: PublicKey,
    connection_epoch: ClientBindingEpoch,
    issued_at: u64,
}

impl ClientBindingBootstrapV1 {
    /// Server-resolved authorization domain pinned by this connection.
    pub const fn authorization_domain(&self) -> CommunityId {
        self.authorization_domain
    }

    /// Authenticated event author pinned by this connection.
    pub const fn event_author_pubkey(&self) -> PublicKey {
        self.event_author_pubkey
    }

    /// Echoed native connection epoch.
    pub fn connection_epoch(&self) -> &ClientBindingEpoch {
        &self.connection_epoch
    }

    /// Relay issue time in Unix seconds.
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }
}

impl fmt::Debug for ClientBindingBootstrapV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientBindingBootstrapV1")
            .field("authorization_domain", &"[redacted]")
            .field("event_author_pubkey", &"[redacted]")
            .field("connection_epoch", &"[redacted]")
            .field("issued_at", &"[redacted]")
            .finish()
    }
}

/// Validated server-side signing input for one connection bootstrap.
pub struct ClientBindingBootstrapInputV1 {
    authorization_domain: CommunityId,
    event_author_pubkey: PublicKey,
    connection_epoch: ClientBindingEpoch,
    issued_at: u64,
}

impl ClientBindingBootstrapInputV1 {
    /// Bind server-resolved connection authority to a native epoch.
    pub fn new(
        authorization_domain: CommunityId,
        event_author_pubkey: PublicKey,
        connection_epoch: ClientBindingEpoch,
        issued_at: u64,
    ) -> Result<Self, ClientBindingBootstrapError> {
        if authorization_domain.as_uuid().is_nil() {
            return Err(ClientBindingBootstrapError::InvalidAuthorizationDomain);
        }
        if issued_at == 0 {
            return Err(ClientBindingBootstrapError::InvalidIssueTime);
        }
        Ok(Self {
            authorization_domain,
            event_author_pubkey,
            connection_epoch,
            issued_at,
        })
    }

    /// Sign the bootstrap with the relay key advertised by NIP-11 `self`.
    pub fn sign_with_relay_keys(
        self,
        relay_keys: &Keys,
    ) -> Result<Event, ClientBindingBootstrapBuildError> {
        let wire = WireClientBindingBootstrapV1 {
            version: CLIENT_BINDING_BOOTSTRAP_VERSION,
            authorization_domain: self.authorization_domain.as_uuid().to_string(),
            event_author_pubkey: self.event_author_pubkey.to_hex(),
            connection_epoch: self.connection_epoch.0,
            issued_at: self.issued_at,
        };
        let content = serde_json::to_string(&wire)
            .map_err(|_| ClientBindingBootstrapBuildError::Serialization)?;
        if content.len() > MAX_CLIENT_BINDING_BOOTSTRAP_PAYLOAD_BYTES {
            return Err(ClientBindingBootstrapBuildError::PayloadTooLarge);
        }
        EventBuilder::new(Kind::Custom(KIND_CLIENT_BINDING_BOOTSTRAP as u16), content)
            .tags([])
            .custom_created_at(Timestamp::from(wire.issued_at))
            .sign_with_keys(relay_keys)
            .map_err(|_| ClientBindingBootstrapBuildError::Signing)
    }
}

impl fmt::Debug for ClientBindingBootstrapInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientBindingBootstrapInputV1")
            .field("authorization_domain", &"[redacted]")
            .field("event_author_pubkey", &"[redacted]")
            .field("connection_epoch", &"[redacted]")
            .field("issued_at", &"[redacted]")
            .finish()
    }
}

#[derive(Deserialize)]
struct VersionHeader {
    version: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireClientBindingBootstrapV1 {
    version: u64,
    authorization_domain: String,
    event_author_pubkey: String,
    connection_epoch: String,
    issued_at: u64,
}

/// Authenticate and validate a connection bootstrap against native authority.
pub fn validate_client_binding_bootstrap_event(
    event: &Event,
    trusted_relay_pubkey: &PublicKey,
    expected_connection_epoch: &ClientBindingEpoch,
    expected_event_author_pubkey: &PublicKey,
    now: u64,
) -> Result<ClientBindingBootstrapV1, ClientBindingBootstrapError> {
    if event.kind.as_u16() as u32 != KIND_CLIENT_BINDING_BOOTSTRAP {
        return Err(ClientBindingBootstrapError::WrongKind);
    }
    if event.content.len() > MAX_CLIENT_BINDING_BOOTSTRAP_PAYLOAD_BYTES {
        return Err(ClientBindingBootstrapError::PayloadTooLarge);
    }
    verify_event(event).map_err(|_| ClientBindingBootstrapError::UnauthenticatedEvent)?;
    if event.pubkey != *trusted_relay_pubkey {
        return Err(ClientBindingBootstrapError::UnexpectedRelay);
    }
    if !event.tags.is_empty() {
        return Err(ClientBindingBootstrapError::UnexpectedTags);
    }
    let header: VersionHeader = serde_json::from_str(&event.content)
        .map_err(|_| ClientBindingBootstrapError::MalformedPayload)?;
    if header.version != CLIENT_BINDING_BOOTSTRAP_VERSION {
        return Err(ClientBindingBootstrapError::UnsupportedVersion);
    }
    let wire: WireClientBindingBootstrapV1 = serde_json::from_str(&event.content)
        .map_err(|_| ClientBindingBootstrapError::MalformedPayload)?;
    let authorization_domain = Uuid::parse_str(&wire.authorization_domain)
        .map_err(|_| ClientBindingBootstrapError::InvalidAuthorizationDomain)?;
    if authorization_domain.is_nil()
        || authorization_domain.to_string() != wire.authorization_domain
    {
        return Err(ClientBindingBootstrapError::InvalidAuthorizationDomain);
    }
    let event_author_pubkey = parse_canonical_pubkey(&wire.event_author_pubkey)?;
    if event_author_pubkey != *expected_event_author_pubkey {
        return Err(ClientBindingBootstrapError::EventAuthorMismatch);
    }
    let connection_epoch = ClientBindingEpoch::parse(&wire.connection_epoch)?;
    if connection_epoch != *expected_connection_epoch {
        return Err(ClientBindingBootstrapError::ConnectionEpochMismatch);
    }
    if wire.issued_at == 0 {
        return Err(ClientBindingBootstrapError::InvalidIssueTime);
    }
    if event.created_at.as_secs() != wire.issued_at {
        return Err(ClientBindingBootstrapError::EventTimeMismatch);
    }
    if wire.issued_at > now {
        return Err(ClientBindingBootstrapError::NotYetValid);
    }
    Ok(ClientBindingBootstrapV1 {
        authorization_domain: CommunityId::from_uuid(authorization_domain),
        event_author_pubkey,
        connection_epoch,
        issued_at: wire.issued_at,
    })
}

fn parse_canonical_pubkey(value: &str) -> Result<PublicKey, ClientBindingBootstrapError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ClientBindingBootstrapError::InvalidEventAuthorPubkey);
    }
    PublicKey::from_hex(value).map_err(|_| ClientBindingBootstrapError::InvalidEventAuthorPubkey)
}

/// Fail-closed bootstrap validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ClientBindingBootstrapError {
    /// Event kind was not the dedicated bootstrap kind.
    #[error("client binding bootstrap event has the wrong kind")]
    WrongKind,
    /// Payload exceeded the public bound.
    #[error("client binding bootstrap payload is too large")]
    PayloadTooLarge,
    /// Event signature or identifier was invalid.
    #[error("client binding bootstrap event is not authenticated")]
    UnauthenticatedEvent,
    /// Signer did not match NIP-11 `self`.
    #[error("client binding bootstrap signer is not the trusted relay")]
    UnexpectedRelay,
    /// Bootstrap events must have no tags.
    #[error("client binding bootstrap contains unexpected tags")]
    UnexpectedTags,
    /// Payload was not the bounded v1 shape.
    #[error("client binding bootstrap payload is malformed")]
    MalformedPayload,
    /// Wire version is unsupported.
    #[error("client binding bootstrap version is unsupported")]
    UnsupportedVersion,
    /// Authorization domain was nil or noncanonical.
    #[error("client binding bootstrap authorization domain is invalid")]
    InvalidAuthorizationDomain,
    /// Event-author key was noncanonical.
    #[error("client binding bootstrap event author is invalid")]
    InvalidEventAuthorPubkey,
    /// Authenticated author did not match native signing state.
    #[error("client binding bootstrap event author does not match")]
    EventAuthorMismatch,
    /// Connection epoch was noncanonical.
    #[error("client binding bootstrap connection epoch is invalid")]
    InvalidConnectionEpoch,
    /// Echoed epoch did not match the native upgrade header.
    #[error("client binding bootstrap connection epoch does not match")]
    ConnectionEpochMismatch,
    /// Issue time was zero.
    #[error("client binding bootstrap issue time is invalid")]
    InvalidIssueTime,
    /// Signed timestamp did not equal the payload timestamp.
    #[error("client binding bootstrap event time does not match")]
    EventTimeMismatch,
    /// Bootstrap claims a future issue time.
    #[error("client binding bootstrap is not yet valid")]
    NotYetValid,
}

/// Bootstrap serialization or signing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ClientBindingBootstrapBuildError {
    /// JSON serialization failed.
    #[error("client binding bootstrap serialization failed")]
    Serialization,
    /// Serialized payload exceeded its public bound.
    #[error("client binding bootstrap payload is too large")]
    PayloadTooLarge,
    /// Relay signing failed.
    #[error("client binding bootstrap signing failed")]
    Signing,
}
