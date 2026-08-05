//! Atomic persistence for the disabled operator lifecycle surface.
//!
//! Authentication and capability policy remain deployment-owned. This module
//! consumes only intent-bound, pseudonymous authority evidence. It serializes
//! operations per authorization domain and commits lifecycle state, authority
//! consumption, immutable receipt, audit outbox event, and effect intent in a
//! single PostgreSQL transaction.

use std::fmt;

use buzz_audit::authorization::{
    ActorReference, AttemptId, AuthorizationEventV1, CapacityClass, CorrelationId, DecisionReason,
    EffectId, EventId, EventKind, EventPayloadV1, EventResult, LifecycleEvidenceV1, OperationClass,
    OperationId, PseudonymousReference, ReferenceKind, SourceClass, TransportClass,
    VersionVectorV1,
};
use buzz_core::CommunityId;
use chrono::{DateTime, Utc};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::{Postgres, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::authorization_evidence::{append_decision_tx, append_outbox_tx};
use crate::authorization_invalidation::{
    authorization_invalidation_request_fingerprint, AuthorizationInvalidationEntry,
    AuthorizationInvalidationRequest,
};
use crate::{Db, DbError, Result};

const MAX_RECORDS: usize = 100;

/// Secret namespace used only for stable access-controlled binding references.
pub struct OperatorReferenceKey {
    bytes: [u8; 32],
    epoch: u32,
}

impl OperatorReferenceKey {
    /// Bind a nonzero key epoch to already generated secret bytes.
    pub fn new(bytes: [u8; 32], epoch: u32) -> Result<Self> {
        if bytes == [0; 32] || epoch == 0 {
            return Err(DbError::InvalidData(
                "operator reference key and epoch must be valid".into(),
            ));
        }
        Ok(Self { bytes, epoch })
    }

    /// Active reference-key epoch.
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    fn derive(&self, domain: CommunityId, binding_id: Uuid) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.bytes)
            .expect("HMAC accepts a 32-byte key");
        Mac::update(&mut mac, b"buzz-operator-binding-reference-v1");
        Mac::update(&mut mac, domain.as_uuid().as_bytes());
        Mac::update(&mut mac, &self.epoch.to_be_bytes());
        Mac::update(&mut mac, binding_id.as_bytes());
        mac.finalize().into_bytes().into()
    }
}

impl fmt::Debug for OperatorReferenceKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorReferenceKey")
            .field("bytes", &"[redacted]")
            .field("epoch", &self.epoch)
            .finish()
    }
}

impl Drop for OperatorReferenceKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Closed operations supported by the initial reachable surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum OperatorLifecycleAction {
    /// List active and historical bindings.
    List = 1,
    /// Preview one exact rotation.
    Preview = 2,
    /// Revoke one exact binding.
    Revoke = 3,
    /// Rotate one exact binding to a freshly proven key.
    Rotate = 4,
}

/// Closed result status retained in an immutable receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum OperatorLifecycleStatus {
    /// Listing completed.
    Listed = 1,
    /// Preview completed.
    Previewed = 2,
    /// Binding was revoked.
    Revoked = 3,
    /// Binding was rotated.
    Rotated = 4,
    /// Operation was denied without mutation.
    Denied = 5,
}

/// Closed redacted binding state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum OperatorBindingState {
    /// Active binding.
    Active = 1,
    /// Revoked binding.
    Revoked = 2,
    /// Rotated binding.
    Rotated = 3,
    /// Archived binding.
    Archived = 4,
}

/// One redacted listing record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperatorLifecycleRecord {
    /// Stable access-controlled reference.
    pub reference: [u8; 32],
    /// Current lifecycle state.
    pub state: OperatorBindingState,
    /// Binding-local monotonic revision.
    pub revision: u64,
}

/// Fresh replacement material supplied only by the authenticated grant.
pub struct VerifiedOperatorReplacement {
    reference: [u8; 32],
    pubkey: [u8; 32],
    policy_digest: [u8; 32],
}

impl VerifiedOperatorReplacement {
    /// Preserve a grant-bound replacement reference, proven key, and policy digest.
    pub fn new(reference: [u8; 32], pubkey: [u8; 32], policy_digest: [u8; 32]) -> Result<Self> {
        if reference == [0; 32] || pubkey == [0; 32] || policy_digest == [0; 32] {
            return Err(DbError::InvalidData(
                "operator replacement evidence is invalid".into(),
            ));
        }
        Ok(Self {
            reference,
            pubkey,
            policy_digest,
        })
    }
}

impl fmt::Debug for VerifiedOperatorReplacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedOperatorReplacement([redacted])")
    }
}

/// Complete authenticated evidence consumed by PostgreSQL.
pub struct OperatorAuthorityEvidence {
    /// Single-use authority evidence identity.
    pub evidence_id: Uuid,
    /// Audit-only actor pseudonym.
    pub actor: PseudonymousReference,
    /// Kind-neutral opaque actor reference used only for independence checks.
    pub actor_independence_reference: [u8; 32],
    /// Pseudonymous credential/provenance reference.
    pub provenance_reference: [u8; 32],
    /// Independently authenticated approver pseudonyms.
    pub approvers: Vec<PseudonymousReference>,
    /// Kind-neutral opaque approver references, parallel to `approvers`.
    pub approver_independence_references: Vec<[u8; 32]>,
    /// Single-use approval evidence identities, parallel to `approvers`.
    pub approval_ids: Vec<Uuid>,
    /// Exclusive trusted expiry rechecked using database time and at commit.
    pub expires_at: DateTime<Utc>,
}

impl fmt::Debug for OperatorAuthorityEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorAuthorityEvidence")
            .field("evidence_id", &"[redacted]")
            .field("actor", &"[redacted]")
            .field("actor_independence_reference", &"[redacted]")
            .field("provenance_reference", &"[redacted]")
            .field("approver_count", &self.approvers.len())
            .field("approver_independence_references", &"[redacted]")
            .field("approval_ids", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// One fully authorized operator command.
pub struct OperatorLifecycleCommand {
    /// Server-resolved domain.
    pub domain: CommunityId,
    /// Stable semantic idempotency identity.
    pub operation_id: Uuid,
    /// Attempt correlation identity, distinct from operation identity.
    pub correlation_id: Uuid,
    /// Stable semantic intent digest.
    pub semantic_fingerprint: [u8; 32],
    /// Exact expected domain lifecycle revision.
    pub expected_revision: u64,
    /// Closed action.
    pub action: OperatorLifecycleAction,
    /// Closed provider-neutral reason discriminant.
    pub reason_code: u16,
    /// Exact target reference when the action requires one.
    pub target_reference: Option<[u8; 32]>,
    /// Audit-only target pseudonym, bound to `target_reference` by the caller.
    pub target_pseudonym: Option<PseudonymousReference>,
    /// Requested replacement reference for preview or rotation.
    pub replacement_reference: Option<[u8; 32]>,
    /// Authenticator-supplied fresh replacement proof for rotation.
    pub replacement: Option<VerifiedOperatorReplacement>,
    /// Bounded list size.
    pub list_limit: u16,
    /// Optional stable listing cursor.
    pub list_after: Option<[u8; 32]>,
    /// Intent-bound authority and approvals.
    pub authority: OperatorAuthorityEvidence,
}

/// Redaction-safe authenticated denial accepted without lifecycle mutation.
pub struct OperatorLifecycleDenialAttempt {
    /// Server-resolved domain.
    pub domain: CommunityId,
    /// Stable operation identity.
    pub operation_id: Uuid,
    /// Attempt correlation identity.
    pub correlation_id: Uuid,
    /// Stable semantic intent digest.
    pub semantic_fingerprint: [u8; 32],
    /// Requested lifecycle revision fence.
    pub expected_revision: u64,
    /// Closed attempted action.
    pub action: OperatorLifecycleAction,
    /// Closed provider-neutral purpose.
    pub reason_code: u16,
    /// Audit-only actor pseudonym.
    pub actor: PseudonymousReference,
    /// Pseudonymous credential/provenance reference.
    pub provenance_reference: [u8; 32],
    /// Independently authenticated approver pseudonyms, if resolved.
    pub approvers: Vec<PseudonymousReference>,
    /// Closed denial reason.
    pub denial_reason: DecisionReason,
}

impl fmt::Debug for OperatorLifecycleDenialAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorLifecycleDenialAttempt")
            .field("domain", &"[redacted]")
            .field("operation_id", &"[redacted]")
            .field("correlation_id", &"[redacted]")
            .field("semantic_fingerprint", &"[redacted]")
            .field("expected_revision", &self.expected_revision)
            .field("action", &self.action)
            .field("reason_code", &self.reason_code)
            .field("actor", &"[redacted]")
            .field("provenance_reference", &"[redacted]")
            .field("approver_count", &self.approvers.len())
            .field("denial_reason", &self.denial_reason)
            .finish()
    }
}

impl fmt::Debug for OperatorLifecycleCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorLifecycleCommand")
            .field("domain", &"[redacted]")
            .field("operation_id", &"[redacted]")
            .field("correlation_id", &"[redacted]")
            .field("semantic_fingerprint", &"[redacted]")
            .field("expected_revision", &self.expected_revision)
            .field("action", &self.action)
            .field("reason_code", &self.reason_code)
            .field("target_reference", &"[redacted]")
            .field("target_pseudonym", &"[redacted]")
            .field("replacement_reference", &"[redacted]")
            .field("replacement", &"[redacted]")
            .field("list_limit", &self.list_limit)
            .field("list_after", &"[redacted]")
            .field("authority", &self.authority)
            .finish()
    }
}

/// Redaction-safe immutable result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorLifecycleResult {
    /// Operation identity.
    pub operation_id: Uuid,
    /// Original correlation identity.
    pub correlation_id: Uuid,
    /// Completed action.
    pub action: OperatorLifecycleAction,
    /// Closed status.
    pub status: OperatorLifecycleStatus,
    /// Bounded affected count.
    pub affected_count: u32,
    /// Domain lifecycle revision after the operation.
    pub lifecycle_revision: u64,
    /// Listing records, empty for every non-list action.
    pub records: Vec<OperatorLifecycleRecord>,
}

/// Fail-closed execution result.
#[derive(Debug, Error)]
pub enum OperatorLifecycleFailure {
    /// Trusted evidence, replay, or expected state denied the operation.
    #[error("operator lifecycle denied: {0:?}")]
    Denied(DecisionReason),
    /// Storage failed; no successful mutation result is exposed.
    #[error("operator lifecycle storage unavailable")]
    Storage(#[source] DbError),
}

impl From<DbError> for OperatorLifecycleFailure {
    fn from(value: DbError) -> Self {
        Self::Storage(value)
    }
}

impl Db {
    /// Execute or replay one operator command atomically.
    pub async fn execute_operator_lifecycle(
        &self,
        key: &OperatorReferenceKey,
        command: &OperatorLifecycleCommand,
    ) -> std::result::Result<OperatorLifecycleResult, OperatorLifecycleFailure> {
        validate_command(command)?;
        let mut tx = self.pool.begin().await.map_err(DbError::from)?;
        ensure_revision_tx(&mut tx, command.domain).await?;
        let revision = lock_revision_tx(&mut tx, command.domain).await?;

        if let Some(existing) = existing_receipt_tx(&mut tx, command).await? {
            if matches!(
                &existing,
                Err(OperatorLifecycleFailure::Denied(
                    DecisionReason::IntentConflict
                ))
            ) {
                let event = operator_event(
                    command,
                    revision,
                    OperatorEventFacts {
                        kind: EventKind::OperatorDenied,
                        result: EventResult::Denied,
                        reason: DecisionReason::IntentConflict,
                        payload: Some(EventPayloadV1::None),
                        summary: None,
                        binding_version: None,
                        invalidation_generation: None,
                    },
                )?;
                append_outbox_tx(&mut tx, &event, CapacityClass::RestrictiveReserve).await?;
            }
            tx.commit().await.map_err(DbError::from)?;
            return existing;
        }

        if let Err(failure) = consume_authority_tx(&mut tx, command).await {
            match failure {
                AuthorityConsumptionFailure::Denied(reason) => {
                    record_denial_tx(&mut tx, command, revision, reason).await?;
                    tx.commit().await.map_err(DbError::from)?;
                    return Err(OperatorLifecycleFailure::Denied(reason));
                }
                AuthorityConsumptionFailure::Storage(error) => {
                    return Err(OperatorLifecycleFailure::Storage(error));
                }
            }
        }
        if command.expected_revision != revision {
            let reason = DecisionReason::StaleExpectedState;
            record_denial_tx(&mut tx, command, revision, reason).await?;
            tx.commit().await.map_err(DbError::from)?;
            return Err(OperatorLifecycleFailure::Denied(reason));
        }

        let outcome = match command.action {
            OperatorLifecycleAction::List => list_tx(&mut tx, key, command, revision).await?,
            OperatorLifecycleAction::Preview => preview_tx(&mut tx, command, revision).await?,
            OperatorLifecycleAction::Revoke => revoke_tx(&mut tx, key, command, revision).await?,
            OperatorLifecycleAction::Rotate => rotate_tx(&mut tx, key, command, revision).await?,
        };
        let outcome = match outcome {
            OperationAttempt::Applied(value) => value,
            OperationAttempt::Denied(reason) => {
                record_denial_tx(&mut tx, command, revision, reason).await?;
                tx.commit().await.map_err(DbError::from)?;
                return Err(OperatorLifecycleFailure::Denied(reason));
            }
        };
        tx.commit().await.map_err(DbError::from)?;
        Ok(outcome)
    }

    /// Durably record one authenticated denial without lifecycle mutation.
    pub async fn record_operator_lifecycle_denial(
        &self,
        attempt: &OperatorLifecycleDenialAttempt,
    ) -> std::result::Result<(), OperatorLifecycleFailure> {
        validate_denial_attempt(attempt)?;
        let mut tx = self.pool.begin().await.map_err(DbError::from)?;
        ensure_revision_tx(&mut tx, attempt.domain).await?;
        let revision = lock_revision_tx(&mut tx, attempt.domain).await?;
        if let Some(existing_fingerprint) = existing_denial_receipt_tx(&mut tx, attempt).await? {
            if existing_fingerprint == attempt.semantic_fingerprint {
                tx.commit().await.map_err(DbError::from)?;
                return Ok(());
            }
            let event = denial_attempt_event(attempt, revision, DecisionReason::IntentConflict)?;
            append_outbox_tx(&mut tx, &event, CapacityClass::RestrictiveReserve).await?;
            tx.commit().await.map_err(DbError::from)?;
            return Ok(());
        }
        let event = denial_attempt_event(attempt, revision, attempt.denial_reason)?;
        append_outbox_tx(&mut tx, &event, CapacityClass::RestrictiveReserve).await?;
        insert_denial_receipt_tx(&mut tx, attempt, revision, event.event_id()).await?;
        tx.commit().await.map_err(DbError::from)?;
        Ok(())
    }
}

enum OperationAttempt {
    Applied(OperatorLifecycleResult),
    Denied(DecisionReason),
}

fn validate_command(
    command: &OperatorLifecycleCommand,
) -> std::result::Result<(), OperatorLifecycleFailure> {
    let mut approver_independence = command.authority.approver_independence_references.clone();
    approver_independence.sort_unstable();
    let invalid_common = command.operation_id.is_nil()
        || command.correlation_id.is_nil()
        || command.semantic_fingerprint == [0; 32]
        || command.expected_revision == 0
        || !(1..=7).contains(&command.reason_code)
        || command.authority.evidence_id.is_nil()
        || command.authority.provenance_reference == [0; 32]
        || command.authority.actor_independence_reference == [0; 32]
        || command.authority.actor.kind() != ReferenceKind::Actor
        || command.authority.approvers.len() != command.authority.approval_ids.len()
        || command.authority.approvers.len()
            != command.authority.approver_independence_references.len()
        || command.authority.approvers.len() > 4
        || command.authority.approval_ids.iter().any(|id| id.is_nil())
        || command
            .authority
            .approver_independence_references
            .contains(&[0; 32])
        || approver_independence
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        || command
            .authority
            .approvers
            .iter()
            .any(|value| value.kind() != ReferenceKind::Approver);
    let invalid_shape = match command.action {
        OperatorLifecycleAction::List => {
            command.list_limit == 0
                || usize::from(command.list_limit) > MAX_RECORDS
                || command.target_reference.is_some()
                || command.target_pseudonym.is_some()
                || command.replacement_reference.is_some()
                || command.replacement.is_some()
        }
        OperatorLifecycleAction::Preview => {
            command.target_reference.is_none()
                || command.target_pseudonym.is_none()
                || command.replacement_reference.is_none()
                || command.replacement.is_none()
                || command.list_limit != 1
                || command.list_after.is_some()
        }
        OperatorLifecycleAction::Revoke => {
            command.target_reference.is_none()
                || command.target_pseudonym.is_none()
                || command.replacement_reference.is_some()
                || command.replacement.is_some()
                || command.list_limit != 1
                || command.list_after.is_some()
        }
        OperatorLifecycleAction::Rotate => {
            command.target_reference.is_none()
                || command.target_pseudonym.is_none()
                || command.replacement_reference.is_none()
                || command.replacement.is_none()
                || command.list_limit != 1
                || command.list_after.is_some()
        }
    };
    if invalid_common || invalid_shape {
        return Err(OperatorLifecycleFailure::Denied(
            DecisionReason::EvidenceInvalid,
        ));
    }
    if command
        .target_pseudonym
        .is_some_and(|value| value.kind() != ReferenceKind::Binding)
    {
        return Err(OperatorLifecycleFailure::Denied(
            DecisionReason::EvidenceInvalid,
        ));
    }
    if let Some(replacement) = &command.replacement {
        if Some(replacement.reference) != command.replacement_reference {
            return Err(OperatorLifecycleFailure::Denied(
                DecisionReason::IntentConflict,
            ));
        }
    }
    Ok(())
}

fn validate_denial_attempt(
    attempt: &OperatorLifecycleDenialAttempt,
) -> std::result::Result<(), OperatorLifecycleFailure> {
    let invalid = attempt.operation_id.is_nil()
        || attempt.correlation_id.is_nil()
        || attempt.semantic_fingerprint == [0; 32]
        || attempt.expected_revision == 0
        || !(1..=7).contains(&attempt.reason_code)
        || attempt.actor.kind() != ReferenceKind::Actor
        || attempt.provenance_reference == [0; 32]
        || attempt.approvers.len() > 4
        || attempt
            .approvers
            .iter()
            .any(|value| value.kind() != ReferenceKind::Approver);
    if invalid {
        return Err(OperatorLifecycleFailure::Denied(
            DecisionReason::EvidenceInvalid,
        ));
    }
    Ok(())
}

async fn ensure_revision_tx(tx: &mut Transaction<'_, Postgres>, domain: CommunityId) -> Result<()> {
    sqlx::query(
        "INSERT INTO authorization_operator_lifecycle_revisions (community_id) \
         VALUES ($1) ON CONFLICT (community_id) DO NOTHING",
    )
    .bind(domain.as_uuid())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn lock_revision_tx(tx: &mut Transaction<'_, Postgres>, domain: CommunityId) -> Result<u64> {
    let value: i64 = sqlx::query_scalar(
        "SELECT revision FROM authorization_operator_lifecycle_revisions \
         WHERE community_id=$1 FOR UPDATE",
    )
    .bind(domain.as_uuid())
    .fetch_one(&mut **tx)
    .await?;
    positive_u64(value, "lifecycle revision")
}

async fn existing_receipt_tx(
    tx: &mut Transaction<'_, Postgres>,
    command: &OperatorLifecycleCommand,
) -> Result<Option<std::result::Result<OperatorLifecycleResult, OperatorLifecycleFailure>>> {
    let row = sqlx::query(
        "SELECT semantic_fingerprint, correlation_id, action, outcome_status, \
                decision_reason, affected_count, lifecycle_revision \
         FROM authorization_operator_operation_receipts \
         WHERE community_id=$1 AND operation_id=$2 FOR SHARE",
    )
    .bind(command.domain.as_uuid())
    .bind(command.operation_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let fingerprint = digest(row.try_get("semantic_fingerprint")?)?;
    if fingerprint != command.semantic_fingerprint {
        return Ok(Some(Err(OperatorLifecycleFailure::Denied(
            DecisionReason::IntentConflict,
        ))));
    }
    let status = parse_status(row.try_get("outcome_status")?)?;
    let reason = parse_reason(row.try_get("decision_reason")?)?;
    if status == OperatorLifecycleStatus::Denied {
        return Ok(Some(Err(OperatorLifecycleFailure::Denied(reason))));
    }
    let action = parse_action(row.try_get("action")?)?;
    let records = load_result_records_tx(tx, command.domain, command.operation_id).await?;
    Ok(Some(Ok(OperatorLifecycleResult {
        operation_id: command.operation_id,
        correlation_id: row.try_get("correlation_id")?,
        action,
        status,
        affected_count: positive_u32(row.try_get("affected_count")?, "affected count")?,
        lifecycle_revision: positive_u64(row.try_get("lifecycle_revision")?, "lifecycle revision")?,
        records,
    })))
}

async fn existing_denial_receipt_tx(
    tx: &mut Transaction<'_, Postgres>,
    attempt: &OperatorLifecycleDenialAttempt,
) -> Result<Option<[u8; 32]>> {
    let value = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT semantic_fingerprint FROM authorization_operator_operation_receipts \
         WHERE community_id=$1 AND operation_id=$2 FOR SHARE",
    )
    .bind(attempt.domain.as_uuid())
    .bind(attempt.operation_id)
    .fetch_optional(&mut **tx)
    .await?;
    value.map(digest).transpose()
}

enum AuthorityConsumptionFailure {
    Denied(DecisionReason),
    Storage(DbError),
}

impl From<DbError> for AuthorityConsumptionFailure {
    fn from(value: DbError) -> Self {
        Self::Storage(value)
    }
}

async fn consume_authority_tx(
    tx: &mut Transaction<'_, Postgres>,
    command: &OperatorLifecycleCommand,
) -> std::result::Result<(), AuthorityConsumptionFailure> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await
        .map_err(DbError::from)?;
    if command.authority.expires_at <= now {
        return Err(AuthorityConsumptionFailure::Denied(
            DecisionReason::StaleApproval,
        ));
    }
    if matches!(
        command.action,
        OperatorLifecycleAction::Revoke | OperatorLifecycleAction::Rotate
    ) && command.authority.approvers.is_empty()
    {
        return Err(AuthorityConsumptionFailure::Denied(
            DecisionReason::MissingApproval,
        ));
    }
    if command
        .authority
        .approver_independence_references
        .contains(&command.authority.actor_independence_reference)
    {
        return Err(AuthorityConsumptionFailure::Denied(
            DecisionReason::SelfApproval,
        ));
    }
    let inserted = sqlx::query(
        "INSERT INTO authorization_operator_authority_consumptions \
         (community_id,evidence_id,operation_id,actor_reference,intent_digest,evidence_expires_at) \
         VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (community_id,evidence_id) DO NOTHING",
    )
    .bind(command.domain.as_uuid())
    .bind(command.authority.evidence_id)
    .bind(command.operation_id)
    .bind(command.authority.actor.digest().as_slice())
    .bind(command.semantic_fingerprint.as_slice())
    .bind(command.authority.expires_at)
    .execute(&mut **tx)
    .await
    .map_err(DbError::from)?;
    if inserted.rows_affected() != 1 {
        return Err(AuthorityConsumptionFailure::Denied(
            DecisionReason::EvidenceReplayed,
        ));
    }
    for (approval_id, approver) in command
        .authority
        .approval_ids
        .iter()
        .zip(&command.authority.approvers)
    {
        let inserted = sqlx::query(
            "INSERT INTO authorization_operator_approval_consumptions \
             (community_id,approval_id,operation_id,approver_reference,intent_digest,approval_expires_at) \
             VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (community_id,approval_id) DO NOTHING",
        )
        .bind(command.domain.as_uuid())
        .bind(approval_id)
        .bind(command.operation_id)
        .bind(approver.digest().as_slice())
        .bind(command.semantic_fingerprint.as_slice())
        .bind(command.authority.expires_at)
        .execute(&mut **tx)
        .await
        .map_err(DbError::from)?;
        if inserted.rows_affected() != 1 {
            return Err(AuthorityConsumptionFailure::Denied(
                DecisionReason::ReplayedApproval,
            ));
        }
    }
    Ok(())
}

async fn list_tx(
    tx: &mut Transaction<'_, Postgres>,
    key: &OperatorReferenceKey,
    command: &OperatorLifecycleCommand,
    revision: u64,
) -> Result<OperationAttempt> {
    let after_binding = match command.list_after {
        Some(reference) => resolve_binding_id_tx(tx, command.domain, reference).await?,
        None => None,
    };
    let rows = sqlx::query(
        "SELECT binding_id,binding_state,binding_version FROM identity_bindings \
         WHERE community_id=$1 AND ($2::UUID IS NULL OR binding_id>$2) \
         ORDER BY binding_id LIMIT $3",
    )
    .bind(command.domain.as_uuid())
    .bind(after_binding)
    .bind(i64::from(command.list_limit))
    .fetch_all(&mut **tx)
    .await?;
    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        let binding_id: Uuid = row.try_get("binding_id")?;
        let reference = binding_reference_tx(tx, key, command.domain, binding_id).await?;
        records.push(OperatorLifecycleRecord {
            reference,
            state: parse_binding_state(row.try_get("binding_state")?)?,
            revision: positive_u64(row.try_get("binding_version")?, "binding revision")?,
        });
    }
    let result = OperatorLifecycleResult {
        operation_id: command.operation_id,
        correlation_id: command.correlation_id,
        action: command.action,
        status: OperatorLifecycleStatus::Listed,
        affected_count: u32::try_from(records.len())
            .map_err(|_| DbError::InvalidData("operator result count exceeded".into()))?,
        lifecycle_revision: revision,
        records,
    };
    accept_success_tx(tx, command, &result, None, None).await?;
    Ok(OperationAttempt::Applied(result))
}

async fn preview_tx(
    tx: &mut Transaction<'_, Postgres>,
    command: &OperatorLifecycleCommand,
    revision: u64,
) -> Result<OperationAttempt> {
    let target = command.target_reference.expect("validated preview target");
    let replacement = command
        .replacement
        .as_ref()
        .expect("validated preview replacement proof");
    let Some(binding) = resolve_active_binding_tx(tx, command.domain, target).await? else {
        return Ok(OperationAttempt::Denied(DecisionReason::TargetMismatch));
    };
    if replacement_ineligible_tx(tx, command.domain, &binding, &replacement.pubkey).await? {
        return Ok(OperationAttempt::Denied(DecisionReason::StaleExpectedState));
    }
    let result = OperatorLifecycleResult {
        operation_id: command.operation_id,
        correlation_id: command.correlation_id,
        action: command.action,
        status: OperatorLifecycleStatus::Previewed,
        affected_count: 1,
        lifecycle_revision: revision,
        records: Vec::new(),
    };
    let decision_event = operator_event(
        command,
        revision,
        OperatorEventFacts {
            kind: EventKind::OperatorPreviewed,
            result: EventResult::Previewed,
            reason: DecisionReason::PreviewOnly,
            payload: None,
            summary: Some((1, command.semantic_fingerprint)),
            binding_version: None,
            invalidation_generation: None,
        },
    )?;
    let accepted = append_decision_tx(tx, &decision_event, CapacityClass::NonessentialRead).await?;
    sqlx::query(
        "INSERT INTO authorization_lifecycle_previews \
         (community_id,preview_digest,operation_id,target_reference,replacement_reference, \
          lifecycle_revision,affected_count,expires_at,decision_event_id) \
         VALUES ($1,$2,$3,$4,$5,$6,1,clock_timestamp()+INTERVAL '5 minutes',$7)",
    )
    .bind(command.domain.as_uuid())
    .bind(command.semantic_fingerprint.as_slice())
    .bind(command.operation_id)
    .bind(target.as_slice())
    .bind(
        command
            .replacement_reference
            .expect("validated preview replacement")
            .as_slice(),
    )
    .bind(i64_revision(revision)?)
    .bind(accepted.event_id.as_uuid())
    .execute(&mut **tx)
    .await?;
    accept_success_tx(tx, command, &result, None, None).await?;
    Ok(OperationAttempt::Applied(result))
}

struct BindingRow {
    binding_id: Uuid,
    issuer: String,
    subject: String,
    pubkey: Vec<u8>,
    version: u64,
    provenance: String,
}

async fn revoke_tx(
    tx: &mut Transaction<'_, Postgres>,
    _key: &OperatorReferenceKey,
    command: &OperatorLifecycleCommand,
    revision: u64,
) -> Result<OperationAttempt> {
    let target = command.target_reference.expect("validated revoke target");
    let Some(binding) = resolve_active_binding_tx(tx, command.domain, target).await? else {
        return Ok(OperationAttempt::Denied(DecisionReason::TargetMismatch));
    };
    if has_pending_lineage_tx(tx, command.domain, &binding).await? {
        return Ok(OperationAttempt::Denied(DecisionReason::StaleExpectedState));
    }
    let next_version = binding
        .version
        .checked_add(1)
        .ok_or_else(|| DbError::InvalidData("binding revision exhausted".into()))?;
    retire_pair_tx(tx, command, &binding, next_version).await?;
    let updated = sqlx::query(
        "UPDATE identity_bindings SET binding_version=$3,binding_state='revoked', \
         revoked_at=clock_timestamp(),revoked_by=$4,revoked_reason=$5, \
         revocation_scope='key',updated_at=clock_timestamp() \
         WHERE community_id=$1 AND binding_id=$2 AND binding_state='active' \
           AND revoked_at IS NULL AND binding_version=$6",
    )
    .bind(command.domain.as_uuid())
    .bind(binding.binding_id)
    .bind(i64_revision(next_version)?)
    .bind(command.authority.actor.digest().as_slice())
    .bind(reason_code(command.reason_code))
    .bind(i64_revision(binding.version)?)
    .execute(&mut **tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Ok(OperationAttempt::Denied(DecisionReason::StaleExpectedState));
    }
    insert_pending_tx(tx, command, &binding, next_version).await?;
    append_binding_history_tx(
        tx,
        command,
        &binding,
        next_version,
        "revoked",
        "revoke_binding",
        None,
    )
    .await?;
    let lifecycle_revision = advance_revision_tx(tx, command.domain, revision).await?;
    let result = OperatorLifecycleResult {
        operation_id: command.operation_id,
        correlation_id: command.correlation_id,
        action: command.action,
        status: OperatorLifecycleStatus::Revoked,
        affected_count: 1,
        lifecycle_revision,
        records: Vec::new(),
    };
    accept_success_tx(
        tx,
        command,
        &result,
        Some((target, binding.version, next_version)),
        Some(binding.binding_id),
    )
    .await?;
    Ok(OperationAttempt::Applied(result))
}

async fn rotate_tx(
    tx: &mut Transaction<'_, Postgres>,
    key: &OperatorReferenceKey,
    command: &OperatorLifecycleCommand,
    revision: u64,
) -> Result<OperationAttempt> {
    let target = command.target_reference.expect("validated rotate target");
    let replacement = command.replacement.as_ref().expect("validated replacement");
    let Some(binding) = resolve_active_binding_tx(tx, command.domain, target).await? else {
        return Ok(OperationAttempt::Denied(DecisionReason::TargetMismatch));
    };
    if replacement_ineligible_tx(tx, command.domain, &binding, &replacement.pubkey).await? {
        return Ok(OperationAttempt::Denied(DecisionReason::StaleExpectedState));
    }
    let next_version = binding
        .version
        .checked_add(1)
        .ok_or_else(|| DbError::InvalidData("binding revision exhausted".into()))?;
    let replacement_binding_id = Uuid::new_v4();
    retire_pair_tx(tx, command, &binding, next_version).await?;
    let updated = sqlx::query(
        "UPDATE identity_bindings SET binding_version=$3,binding_state='rotated', \
         revoked_at=clock_timestamp(),revoked_by=$4,revoked_reason=$5, \
         revocation_scope='rotation',rotation_completed_at=clock_timestamp(), \
         rotated_to_pubkey=$6,rotation_by=$4,rotation_reason=$5, \
         replacement_binding_id=$7,updated_at=clock_timestamp() \
         WHERE community_id=$1 AND binding_id=$2 AND binding_state='active' \
           AND revoked_at IS NULL AND binding_version=$8",
    )
    .bind(command.domain.as_uuid())
    .bind(binding.binding_id)
    .bind(i64_revision(next_version)?)
    .bind(command.authority.actor.digest().as_slice())
    .bind(reason_code(command.reason_code))
    .bind(replacement.pubkey.as_slice())
    .bind(replacement_binding_id)
    .bind(i64_revision(binding.version)?)
    .execute(&mut **tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Ok(OperationAttempt::Denied(DecisionReason::StaleExpectedState));
    }
    let policy = hex::encode(replacement.policy_digest);
    sqlx::query(
        "INSERT INTO identity_bindings \
         (community_id,issuer,uid,pubkey,source,binding_id,binding_version,binding_state, \
          binding_provenance,created_by,created_policy_version,creation_attribution_kind) \
         VALUES ($1,$2,$3,$4,'db_binding',$5,1,'active','provisioned',$6,$7,'operator')",
    )
    .bind(command.domain.as_uuid())
    .bind(&binding.issuer)
    .bind(&binding.subject)
    .bind(replacement.pubkey.as_slice())
    .bind(replacement_binding_id)
    .bind(command.authority.actor.digest().as_slice())
    .bind(policy)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO identity_binding_lineage \
         (community_id,predecessor_binding_id,successor_binding_id) VALUES ($1,$2,$3)",
    )
    .bind(command.domain.as_uuid())
    .bind(binding.binding_id)
    .bind(replacement_binding_id)
    .execute(&mut **tx)
    .await?;
    append_binding_history_tx(
        tx,
        command,
        &binding,
        next_version,
        "rotated",
        "rotate",
        Some(replacement_binding_id),
    )
    .await?;
    let replacement_row = BindingRow {
        binding_id: replacement_binding_id,
        issuer: binding.issuer.clone(),
        subject: binding.subject.clone(),
        pubkey: replacement.pubkey.to_vec(),
        version: 1,
        provenance: "provisioned".into(),
    };
    append_binding_history_tx(tx, command, &replacement_row, 1, "active", "rotate", None).await?;
    let _ = binding_reference_tx(tx, key, command.domain, replacement_binding_id).await?;
    let lifecycle_revision = advance_revision_tx(tx, command.domain, revision).await?;
    let result = OperatorLifecycleResult {
        operation_id: command.operation_id,
        correlation_id: command.correlation_id,
        action: command.action,
        status: OperatorLifecycleStatus::Rotated,
        affected_count: 1,
        lifecycle_revision,
        records: Vec::new(),
    };
    accept_success_tx(
        tx,
        command,
        &result,
        Some((target, binding.version, next_version)),
        Some(binding.binding_id),
    )
    .await?;
    Ok(OperationAttempt::Applied(result))
}

async fn apply_binding_invalidation_tx(
    tx: &mut Transaction<'_, Postgres>,
    command: &OperatorLifecycleCommand,
    binding_id: Uuid,
    invalid_through: u64,
) -> Result<u64> {
    let request = AuthorizationInvalidationRequest::new(
        command.operation_id,
        vec![
            AuthorizationInvalidationEntry::binding_version_floor(binding_id, invalid_through)?,
            AuthorizationInvalidationEntry::domain_fence(),
        ],
    )?;
    let fingerprint = authorization_invalidation_request_fingerprint(command.domain, &request);
    sqlx::query(
        "INSERT INTO authorization_invalidation_domains (community_id) \
         VALUES ($1) ON CONFLICT (community_id) DO NOTHING",
    )
    .bind(command.domain.as_uuid())
    .execute(&mut **tx)
    .await?;
    let generation: i64 = sqlx::query_scalar(
        "SELECT generation FROM authorization_invalidation_domains \
         WHERE community_id=$1 FOR UPDATE",
    )
    .bind(command.domain.as_uuid())
    .fetch_one(&mut **tx)
    .await?;
    if let Some(row) = sqlx::query(
        "SELECT generation,request_fingerprint FROM authorization_invalidation_receipts \
         WHERE community_id=$1 AND event_id=$2",
    )
    .bind(command.domain.as_uuid())
    .bind(request.event_id())
    .fetch_optional(&mut **tx)
    .await?
    {
        let stored = digest(row.try_get("request_fingerprint")?)?;
        if stored != fingerprint {
            return Err(DbError::InvalidData(
                "operator invalidation identity was reused with different input".into(),
            ));
        }
        return positive_u64(row.try_get("generation")?, "invalidation generation");
    }
    let next_generation = generation
        .checked_add(1)
        .ok_or_else(|| DbError::InvalidData("operator invalidation generation exhausted".into()))?;
    sqlx::query(
        "INSERT INTO authorization_invalidation_receipts \
         (community_id,event_id,generation,request_fingerprint) VALUES ($1,$2,$3,$4)",
    )
    .bind(command.domain.as_uuid())
    .bind(request.event_id())
    .bind(next_generation)
    .bind(fingerprint.as_slice())
    .execute(&mut **tx)
    .await?;
    for entry in request.entries() {
        let selector = entry.selector();
        let binding_floor = selector
            .binding_version_floor()
            .map(i64::try_from)
            .transpose()
            .map_err(|_| {
                DbError::InvalidData("operator binding version exceeds database range".into())
            })?;
        sqlx::query(
            "INSERT INTO authorization_invalidation_floors \
             (community_id,selector_kind,selector_fingerprint,generation, \
              sticky_deny,binding_version_floor) VALUES ($1,$2,$3,$4,FALSE,$5) \
             ON CONFLICT (community_id,selector_kind,selector_fingerprint) DO UPDATE SET \
               generation=EXCLUDED.generation, \
               binding_version_floor=CASE \
                 WHEN authorization_invalidation_floors.binding_version_floor IS NULL \
                   THEN EXCLUDED.binding_version_floor \
                 WHEN EXCLUDED.binding_version_floor IS NULL \
                   THEN authorization_invalidation_floors.binding_version_floor \
                 ELSE GREATEST(authorization_invalidation_floors.binding_version_floor, \
                               EXCLUDED.binding_version_floor) END, \
               updated_at=NOW()",
        )
        .bind(command.domain.as_uuid())
        .bind(selector.kind().as_str())
        .bind(selector.fingerprint().as_slice())
        .bind(next_generation)
        .bind(binding_floor)
        .execute(&mut **tx)
        .await?;
    }
    sqlx::query(
        "UPDATE authorization_invalidation_domains SET generation=$2,updated_at=NOW() \
         WHERE community_id=$1",
    )
    .bind(command.domain.as_uuid())
    .bind(next_generation)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO authorization_operation_receipts \
         (community_id,operation_id,operation_kind,request_fingerprint,result_payload, \
          lease_expires_at) VALUES ($1,$2,'authorization.invalidation',$3,$4, \
          clock_timestamp()+INTERVAL '100 years')",
    )
    .bind(command.domain.as_uuid())
    .bind(command.operation_id)
    .bind(fingerprint.as_slice())
    .bind(next_generation.to_be_bytes().as_slice())
    .execute(&mut **tx)
    .await?;
    positive_u64(next_generation, "invalidation generation")
}

async fn accept_success_tx(
    tx: &mut Transaction<'_, Postgres>,
    command: &OperatorLifecycleCommand,
    result: &OperatorLifecycleResult,
    lifecycle: Option<([u8; 32], u64, u64)>,
    binding_id: Option<Uuid>,
) -> Result<()> {
    let invalidation_generation = match (lifecycle, binding_id) {
        (Some((_, _, current)), Some(binding_id)) => {
            Some(apply_binding_invalidation_tx(tx, command, binding_id, current).await?)
        }
        (None, None) => None,
        _ => {
            return Err(DbError::InvalidData(
                "operator lifecycle invalidation target is incomplete".into(),
            ));
        }
    };
    let effect_id = lifecycle.map(|_| EffectId::generate());
    let payload = lifecycle
        .map(|(reference, previous, current)| {
            let target = command_target_pseudonym(command, reference)?;
            LifecycleEvidenceV1::new(
                target,
                Some(previous),
                Some(current),
                None,
                effect_id,
                invalidation_generation,
                None,
            )
            .map(EventPayloadV1::Lifecycle)
            .map_err(|error| DbError::InvalidData(error.to_string()))
        })
        .transpose()?
        .unwrap_or(EventPayloadV1::BoundedSummary {
            count: result.affected_count,
            snapshot_digest: command.semantic_fingerprint,
        });
    let event = operator_event(
        command,
        result.lifecycle_revision,
        OperatorEventFacts {
            kind: event_kind(result.status),
            result: match result.status {
                OperatorLifecycleStatus::Listed => EventResult::NoChange,
                OperatorLifecycleStatus::Previewed => EventResult::Previewed,
                OperatorLifecycleStatus::Revoked | OperatorLifecycleStatus::Rotated => {
                    EventResult::Applied
                }
                OperatorLifecycleStatus::Denied => EventResult::Denied,
            },
            reason: DecisionReason::Applied,
            payload: Some(payload),
            summary: None,
            binding_version: lifecycle.map(|(_, _, current)| current),
            invalidation_generation,
        },
    )?;
    let capacity = if result.status == OperatorLifecycleStatus::Revoked {
        CapacityClass::RestrictiveReserve
    } else {
        CapacityClass::NewAllow
    };
    append_outbox_tx(tx, &event, capacity).await?;
    insert_receipt_tx(
        tx,
        command,
        result,
        DecisionReason::Applied,
        event.event_id(),
    )
    .await?;
    if let (Some(effect_id), Some((target, _, _))) = (effect_id, lifecycle) {
        sqlx::query(
            "INSERT INTO authorization_operator_effects \
             (community_id,effect_id,operation_id,effect_kind,target_reference, \
              lifecycle_revision,audit_event_id) VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(command.domain.as_uuid())
        .bind(effect_id.as_uuid())
        .bind(command.operation_id)
        .bind(match command.action {
            OperatorLifecycleAction::Revoke => 1_i16,
            OperatorLifecycleAction::Rotate => 2_i16,
            _ => return Err(DbError::InvalidData("unexpected operator effect".into())),
        })
        .bind(target.as_slice())
        .bind(i64_revision(result.lifecycle_revision)?)
        .bind(event.event_id().as_uuid())
        .execute(&mut **tx)
        .await?;
    }
    insert_result_records_tx(tx, command.domain, command.operation_id, &result.records).await
}

async fn record_denial_tx(
    tx: &mut Transaction<'_, Postgres>,
    command: &OperatorLifecycleCommand,
    revision: u64,
    reason: DecisionReason,
) -> Result<()> {
    let event = operator_event(
        command,
        revision,
        OperatorEventFacts {
            kind: EventKind::OperatorDenied,
            result: EventResult::Denied,
            reason,
            payload: Some(EventPayloadV1::None),
            summary: None,
            binding_version: None,
            invalidation_generation: None,
        },
    )?;
    append_outbox_tx(tx, &event, CapacityClass::RestrictiveReserve).await?;
    let result = OperatorLifecycleResult {
        operation_id: command.operation_id,
        correlation_id: command.correlation_id,
        action: command.action,
        status: OperatorLifecycleStatus::Denied,
        affected_count: 0,
        lifecycle_revision: revision,
        records: Vec::new(),
    };
    insert_receipt_tx(tx, command, &result, reason, event.event_id()).await
}

struct OperatorEventFacts {
    kind: EventKind,
    result: EventResult,
    reason: DecisionReason,
    payload: Option<EventPayloadV1>,
    summary: Option<(u32, [u8; 32])>,
    binding_version: Option<u64>,
    invalidation_generation: Option<u64>,
}

fn operator_event(
    command: &OperatorLifecycleCommand,
    revision: u64,
    facts: OperatorEventFacts,
) -> Result<AuthorizationEventV1> {
    let actor =
        ActorReference::operator(command.authority.actor, command.authority.approvers.clone())
            .map_err(|error| DbError::InvalidData(error.to_string()))?;
    let payload = facts.payload.unwrap_or_else(|| {
        let (count, snapshot_digest) = facts.summary.unwrap_or((0, command.semantic_fingerprint));
        EventPayloadV1::BoundedSummary {
            count,
            snapshot_digest,
        }
    });
    Ok(AuthorizationEventV1::new(
        EventId::generate(),
        command.domain,
        Utc::now(),
        Some(
            OperationId::from_uuid(command.operation_id)
                .map_err(|error| DbError::InvalidData(error.to_string()))?,
        ),
        CorrelationId::from_uuid(command.correlation_id)
            .map_err(|error| DbError::InvalidData(error.to_string()))?,
        AttemptId::generate(),
        None,
        actor,
        TransportClass::Internal,
        match command.action {
            OperatorLifecycleAction::List => OperationClass::Inspection,
            OperatorLifecycleAction::Preview => OperationClass::Preview,
            OperatorLifecycleAction::Revoke | OperatorLifecycleAction::Rotate => {
                OperationClass::Lifecycle
            }
        },
        SourceClass::Lifecycle,
        facts.kind,
        facts.result,
        facts.reason,
        VersionVectorV1 {
            binding: facts.binding_version,
            lifecycle: Some(revision),
            invalidation: facts.invalidation_generation,
            ..VersionVectorV1::default()
        },
        payload,
    ))
}

fn command_target_pseudonym(
    command: &OperatorLifecycleCommand,
    reference: [u8; 32],
) -> Result<PseudonymousReference> {
    command
        .target_reference
        .filter(|value| *value == reference)
        .and(command.target_pseudonym)
        .ok_or_else(|| DbError::InvalidData("operator target evidence mismatch".into()))
}

async fn insert_receipt_tx(
    tx: &mut Transaction<'_, Postgres>,
    command: &OperatorLifecycleCommand,
    result: &OperatorLifecycleResult,
    reason: DecisionReason,
    audit_event_id: EventId,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO authorization_operator_operation_receipts \
         (community_id,operation_id,semantic_fingerprint,correlation_id,action, \
          outcome_status,decision_reason,reason_code,actor_reference,provenance_reference, \
          affected_count,lifecycle_revision,audit_event_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(command.domain.as_uuid())
    .bind(command.operation_id)
    .bind(command.semantic_fingerprint.as_slice())
    .bind(command.correlation_id)
    .bind(command.action as i16)
    .bind(result.status as i16)
    .bind(reason.discriminant() as i16)
    .bind(command.reason_code as i16)
    .bind(command.authority.actor.digest().as_slice())
    .bind(command.authority.provenance_reference.as_slice())
    .bind(
        i32::try_from(result.affected_count)
            .map_err(|_| DbError::InvalidData("operator affected count is out of range".into()))?,
    )
    .bind(i64_revision(result.lifecycle_revision)?)
    .bind(audit_event_id.as_uuid())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_denial_receipt_tx(
    tx: &mut Transaction<'_, Postgres>,
    attempt: &OperatorLifecycleDenialAttempt,
    revision: u64,
    audit_event_id: EventId,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO authorization_operator_operation_receipts \
         (community_id,operation_id,semantic_fingerprint,correlation_id,action, \
          outcome_status,decision_reason,reason_code,actor_reference,provenance_reference, \
          affected_count,lifecycle_revision,audit_event_id) \
         VALUES ($1,$2,$3,$4,$5,5,$6,$7,$8,$9,0,$10,$11)",
    )
    .bind(attempt.domain.as_uuid())
    .bind(attempt.operation_id)
    .bind(attempt.semantic_fingerprint.as_slice())
    .bind(attempt.correlation_id)
    .bind(attempt.action as i16)
    .bind(attempt.denial_reason.discriminant() as i16)
    .bind(attempt.reason_code as i16)
    .bind(attempt.actor.digest().as_slice())
    .bind(attempt.provenance_reference.as_slice())
    .bind(i64_revision(revision)?)
    .bind(audit_event_id.as_uuid())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn denial_attempt_event(
    attempt: &OperatorLifecycleDenialAttempt,
    revision: u64,
    reason: DecisionReason,
) -> Result<AuthorizationEventV1> {
    let actor = ActorReference::operator(attempt.actor, attempt.approvers.clone())
        .map_err(|error| DbError::InvalidData(error.to_string()))?;
    Ok(AuthorizationEventV1::new(
        EventId::generate(),
        attempt.domain,
        Utc::now(),
        Some(
            OperationId::from_uuid(attempt.operation_id)
                .map_err(|error| DbError::InvalidData(error.to_string()))?,
        ),
        CorrelationId::from_uuid(attempt.correlation_id)
            .map_err(|error| DbError::InvalidData(error.to_string()))?,
        AttemptId::generate(),
        None,
        actor,
        TransportClass::Internal,
        match attempt.action {
            OperatorLifecycleAction::List => OperationClass::Inspection,
            OperatorLifecycleAction::Preview => OperationClass::Preview,
            OperatorLifecycleAction::Revoke | OperatorLifecycleAction::Rotate => {
                OperationClass::Lifecycle
            }
        },
        SourceClass::Lifecycle,
        EventKind::OperatorDenied,
        EventResult::Denied,
        reason,
        VersionVectorV1 {
            lifecycle: Some(revision),
            ..VersionVectorV1::default()
        },
        EventPayloadV1::None,
    ))
}

async fn insert_result_records_tx(
    tx: &mut Transaction<'_, Postgres>,
    domain: CommunityId,
    operation_id: Uuid,
    records: &[OperatorLifecycleRecord],
) -> Result<()> {
    for (ordinal, record) in records.iter().enumerate() {
        sqlx::query(
            "INSERT INTO authorization_operator_result_records \
             (community_id,operation_id,ordinal,record_reference,record_state,record_revision) \
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(domain.as_uuid())
        .bind(operation_id)
        .bind(
            i16::try_from(ordinal).map_err(|_| {
                DbError::InvalidData("operator result ordinal is out of range".into())
            })?,
        )
        .bind(record.reference.as_slice())
        .bind(record.state as i16)
        .bind(i64_revision(record.revision)?)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn load_result_records_tx(
    tx: &mut Transaction<'_, Postgres>,
    domain: CommunityId,
    operation_id: Uuid,
) -> Result<Vec<OperatorLifecycleRecord>> {
    let rows = sqlx::query(
        "SELECT record_reference,record_state,record_revision \
         FROM authorization_operator_result_records \
         WHERE community_id=$1 AND operation_id=$2 ORDER BY ordinal",
    )
    .bind(domain.as_uuid())
    .bind(operation_id)
    .fetch_all(&mut **tx)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(OperatorLifecycleRecord {
                reference: digest(row.try_get("record_reference")?)?,
                state: parse_record_state(row.try_get("record_state")?)?,
                revision: positive_u64(row.try_get("record_revision")?, "record revision")?,
            })
        })
        .collect()
}

async fn binding_reference_tx(
    tx: &mut Transaction<'_, Postgres>,
    key: &OperatorReferenceKey,
    domain: CommunityId,
    binding_id: Uuid,
) -> Result<[u8; 32]> {
    if let Some(reference) = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT binding_reference FROM authorization_operator_binding_refs \
         WHERE community_id=$1 AND binding_id=$2",
    )
    .bind(domain.as_uuid())
    .bind(binding_id)
    .fetch_optional(&mut **tx)
    .await?
    {
        return digest(reference);
    }
    let reference = key.derive(domain, binding_id);
    sqlx::query(
        "INSERT INTO authorization_operator_binding_refs \
         (community_id,binding_reference,binding_id,key_epoch) VALUES ($1,$2,$3,$4)",
    )
    .bind(domain.as_uuid())
    .bind(reference.as_slice())
    .bind(binding_id)
    .bind(
        i32::try_from(key.epoch())
            .map_err(|_| DbError::InvalidData("operator reference epoch is out of range".into()))?,
    )
    .execute(&mut **tx)
    .await?;
    Ok(reference)
}

async fn resolve_binding_id_tx(
    tx: &mut Transaction<'_, Postgres>,
    domain: CommunityId,
    reference: [u8; 32],
) -> Result<Option<Uuid>> {
    Ok(sqlx::query_scalar(
        "SELECT binding_id FROM authorization_operator_binding_refs \
         WHERE community_id=$1 AND binding_reference=$2",
    )
    .bind(domain.as_uuid())
    .bind(reference.as_slice())
    .fetch_optional(&mut **tx)
    .await?)
}

async fn resolve_active_binding_tx(
    tx: &mut Transaction<'_, Postgres>,
    domain: CommunityId,
    reference: [u8; 32],
) -> Result<Option<BindingRow>> {
    let row = sqlx::query(
        "SELECT binding.binding_id,binding.issuer,binding.uid,binding.pubkey, \
                binding.binding_version,binding.binding_provenance \
         FROM authorization_operator_binding_refs reference \
         JOIN identity_bindings binding ON binding.community_id=reference.community_id \
              AND binding.binding_id=reference.binding_id \
         WHERE reference.community_id=$1 AND reference.binding_reference=$2 \
           AND binding.binding_state='active' AND binding.revoked_at IS NULL \
         FOR UPDATE OF binding",
    )
    .bind(domain.as_uuid())
    .bind(reference.as_slice())
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        Ok(BindingRow {
            binding_id: row.try_get("binding_id")?,
            issuer: row.try_get("issuer")?,
            subject: row.try_get("uid")?,
            pubkey: row.try_get("pubkey")?,
            version: positive_u64(row.try_get("binding_version")?, "binding version")?,
            provenance: row.try_get("binding_provenance")?,
        })
    })
    .transpose()
}

async fn has_pending_lineage_tx(
    tx: &mut Transaction<'_, Postgres>,
    domain: CommunityId,
    binding: &BindingRow,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM identity_pending_replacements \
         WHERE community_id=$1 AND issuer=$2 AND subject=$3 AND cleared_at IS NULL)",
    )
    .bind(domain.as_uuid())
    .bind(&binding.issuer)
    .bind(&binding.subject)
    .fetch_one(&mut **tx)
    .await?)
}

async fn replacement_denied_tx(
    tx: &mut Transaction<'_, Postgres>,
    domain: CommunityId,
    binding: &BindingRow,
    replacement: &[u8; 32],
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT \
           EXISTS(SELECT 1 FROM identity_principals WHERE community_id=$1 \
                  AND issuer=$2 AND uid=$3 AND disabled_at IS NOT NULL) OR \
           EXISTS(SELECT 1 FROM identity_migration_denials WHERE community_id=$1 \
                  AND issuer=$2 AND subject=$3) OR \
           EXISTS(SELECT 1 FROM identity_revoked_keys WHERE community_id=$1 AND pubkey=$4) OR \
           EXISTS(SELECT 1 FROM identity_migration_denied_keys WHERE community_id=$1 AND pubkey=$4) OR \
           EXISTS(SELECT 1 FROM identity_bindings WHERE community_id=$1 AND pubkey=$4 \
                  AND binding_state='active' AND revoked_at IS NULL) OR \
           EXISTS(SELECT 1 FROM identity_retired_pairs WHERE community_id=$1 \
                  AND issuer=$2 AND subject=$3 AND pubkey=$4) OR \
           EXISTS(SELECT 1 FROM identity_bindings WHERE community_id=$1 \
                  AND issuer=$2 AND uid=$3 AND pubkey=$4 AND revoked_at IS NOT NULL)",
    )
    .bind(domain.as_uuid())
    .bind(&binding.issuer)
    .bind(&binding.subject)
    .bind(replacement.as_slice())
    .fetch_one(&mut **tx)
    .await?)
}

async fn replacement_ineligible_tx(
    tx: &mut Transaction<'_, Postgres>,
    domain: CommunityId,
    binding: &BindingRow,
    replacement: &[u8; 32],
) -> Result<bool> {
    Ok(binding.pubkey.as_slice() == replacement
        || has_pending_lineage_tx(tx, domain, binding).await?
        || replacement_denied_tx(tx, domain, binding, replacement).await?)
}

async fn retire_pair_tx(
    tx: &mut Transaction<'_, Postgres>,
    command: &OperatorLifecycleCommand,
    binding: &BindingRow,
    version: u64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO identity_retired_pairs \
         (community_id,issuer,subject,pubkey,retired_binding_id,retired_binding_version, \
          retired_at,retired_by,reason) \
         VALUES ($1,$2,$3,$4,$5,$6,clock_timestamp(),$7,$8) \
         ON CONFLICT (community_id,issuer,subject,pubkey) DO NOTHING",
    )
    .bind(command.domain.as_uuid())
    .bind(&binding.issuer)
    .bind(&binding.subject)
    .bind(&binding.pubkey)
    .bind(binding.binding_id)
    .bind(i64_revision(version)?)
    .bind(command.authority.actor.digest().as_slice())
    .bind(reason_code(command.reason_code))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_pending_tx(
    tx: &mut Transaction<'_, Postgres>,
    command: &OperatorLifecycleCommand,
    binding: &BindingRow,
    version: u64,
) -> Result<()> {
    let selector: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(selector_version),0)+1 FROM identity_pending_replacements \
         WHERE community_id=$1 AND issuer=$2 AND subject=$3",
    )
    .bind(command.domain.as_uuid())
    .bind(&binding.issuer)
    .bind(&binding.subject)
    .fetch_one(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO identity_pending_replacements \
         (community_id,issuer,subject,selector_version,retired_pubkey,retired_binding_id, \
          retired_binding_version,created_operation_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(command.domain.as_uuid())
    .bind(&binding.issuer)
    .bind(&binding.subject)
    .bind(selector)
    .bind(&binding.pubkey)
    .bind(binding.binding_id)
    .bind(i64_revision(version)?)
    .bind(command.operation_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn append_binding_history_tx(
    tx: &mut Transaction<'_, Postgres>,
    command: &OperatorLifecycleCommand,
    binding: &BindingRow,
    version: u64,
    state: &str,
    transition: &str,
    replacement_binding_id: Option<Uuid>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO identity_binding_history \
         (community_id,binding_id,binding_version,issuer,subject,pubkey,binding_state, \
          binding_provenance,transition_kind,replacement_binding_id,operation_id,actor,reason) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(command.domain.as_uuid())
    .bind(binding.binding_id)
    .bind(i64_revision(version)?)
    .bind(&binding.issuer)
    .bind(&binding.subject)
    .bind(&binding.pubkey)
    .bind(state)
    .bind(&binding.provenance)
    .bind(transition)
    .bind(replacement_binding_id)
    .bind(command.operation_id)
    .bind(command.authority.actor.digest().as_slice())
    .bind(reason_code(command.reason_code))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn advance_revision_tx(
    tx: &mut Transaction<'_, Postgres>,
    domain: CommunityId,
    current: u64,
) -> Result<u64> {
    let next = current
        .checked_add(1)
        .ok_or_else(|| DbError::InvalidData("operator lifecycle revision exhausted".into()))?;
    let updated = sqlx::query(
        "UPDATE authorization_operator_lifecycle_revisions \
         SET revision=$2,updated_at=clock_timestamp() WHERE community_id=$1 AND revision=$3",
    )
    .bind(domain.as_uuid())
    .bind(i64_revision(next)?)
    .bind(i64_revision(current)?)
    .execute(&mut **tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(DbError::InvalidData(
            "operator lifecycle revision changed concurrently".into(),
        ));
    }
    Ok(next)
}

fn event_kind(status: OperatorLifecycleStatus) -> EventKind {
    match status {
        OperatorLifecycleStatus::Listed => EventKind::OperatorListed,
        OperatorLifecycleStatus::Previewed => EventKind::OperatorPreviewed,
        OperatorLifecycleStatus::Revoked => EventKind::OperatorBindingRevoked,
        OperatorLifecycleStatus::Rotated => EventKind::OperatorRotated,
        OperatorLifecycleStatus::Denied => EventKind::OperatorDenied,
    }
}

fn parse_action(value: i16) -> Result<OperatorLifecycleAction> {
    match value {
        1 => Ok(OperatorLifecycleAction::List),
        2 => Ok(OperatorLifecycleAction::Preview),
        3 => Ok(OperatorLifecycleAction::Revoke),
        4 => Ok(OperatorLifecycleAction::Rotate),
        _ => Err(DbError::InvalidData("operator action is invalid".into())),
    }
}

fn parse_status(value: i16) -> Result<OperatorLifecycleStatus> {
    match value {
        1 => Ok(OperatorLifecycleStatus::Listed),
        2 => Ok(OperatorLifecycleStatus::Previewed),
        3 => Ok(OperatorLifecycleStatus::Revoked),
        4 => Ok(OperatorLifecycleStatus::Rotated),
        5 => Ok(OperatorLifecycleStatus::Denied),
        _ => Err(DbError::InvalidData("operator status is invalid".into())),
    }
}

fn parse_binding_state(value: String) -> Result<OperatorBindingState> {
    match value.as_str() {
        "active" => Ok(OperatorBindingState::Active),
        "revoked" => Ok(OperatorBindingState::Revoked),
        "rotated" => Ok(OperatorBindingState::Rotated),
        "archived" => Ok(OperatorBindingState::Archived),
        _ => Err(DbError::InvalidData(
            "operator binding state is invalid".into(),
        )),
    }
}

fn parse_record_state(value: i16) -> Result<OperatorBindingState> {
    match value {
        1 => Ok(OperatorBindingState::Active),
        2 => Ok(OperatorBindingState::Revoked),
        3 => Ok(OperatorBindingState::Rotated),
        4 => Ok(OperatorBindingState::Archived),
        _ => Err(DbError::InvalidData(
            "operator result state is invalid".into(),
        )),
    }
}

fn parse_reason(value: i16) -> Result<DecisionReason> {
    DecisionReason::ALL
        .iter()
        .copied()
        .find(|reason| reason.discriminant() == value as u16)
        .ok_or_else(|| DbError::InvalidData("operator decision reason is invalid".into()))
}

fn reason_code(value: u16) -> &'static str {
    match value {
        1 => "offboarding",
        2 => "compromise_containment",
        3 => "planned_rotation",
        4 => "verified_recovery",
        5 => "integrity_repair",
        6 => "emergency_containment",
        7 => "retention_archive",
        _ => "invalid",
    }
}

fn positive_u64(value: i64, label: &str) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| DbError::InvalidData(format!("operator {label} is out of range")))
}

fn positive_u32(value: i32, label: &str) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| DbError::InvalidData(format!("operator {label} is out of range")))
}

fn i64_revision(value: u64) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| DbError::InvalidData("operator revision is out of range".into()))
}

fn digest(value: Vec<u8>) -> Result<[u8; 32]> {
    value
        .try_into()
        .map_err(|_| DbError::InvalidData("operator digest has invalid length".into()))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use buzz_audit::authorization::{
        ControlCode, DeliveryDisposition, DeliveryKind, ExporterId, PseudonymKey, Pseudonymizer,
        RetryPolicy,
    };

    use crate::test_support::IsolatedPostgres;

    use super::*;

    fn authority(
        pseudonymizer: &Pseudonymizer,
        domain: CommunityId,
        actor_raw: [u8; 32],
        approver_raw: Option<[u8; 32]>,
    ) -> OperatorAuthorityEvidence {
        let approver_values = approver_raw.into_iter().collect::<Vec<_>>();
        OperatorAuthorityEvidence {
            evidence_id: Uuid::new_v4(),
            actor: pseudonymizer
                .derive(domain, ReferenceKind::Actor, &actor_raw)
                .unwrap(),
            actor_independence_reference: actor_raw,
            provenance_reference: [99; 32],
            approvers: approver_values
                .iter()
                .map(|value| {
                    pseudonymizer
                        .derive(domain, ReferenceKind::Approver, value)
                        .unwrap()
                })
                .collect(),
            approver_independence_references: approver_values.clone(),
            approval_ids: approver_values.iter().map(|_| Uuid::new_v4()).collect(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        }
    }

    #[test]
    fn reference_key_is_domain_and_epoch_separated_and_redacted() {
        let first = OperatorReferenceKey::new([7; 32], 1).unwrap();
        let second = OperatorReferenceKey::new([7; 32], 2).unwrap();
        let binding = Uuid::new_v4();
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        assert_ne!(
            first.derive(domain, binding),
            second.derive(domain, binding)
        );
        assert!(format!("{first:?}").contains("[redacted]"));
    }

    #[test]
    fn migrations_keep_results_closed_and_previews_in_decision_lane() {
        let lifecycle =
            include_str!("../../../migrations/0049_authorization_operator_lifecycle.sql");
        let previews =
            include_str!("../../../migrations/0050_authorization_lifecycle_previews.sql");
        assert!(!lifecycle.contains("JSONB"));
        assert!(lifecycle.contains("authorization_operator_operation_receipts"));
        assert!(previews.contains("authorization_decision_events"));
    }

    #[tokio::test]
    async fn postgres_operator_lifecycle_is_atomic_idempotent_and_serialized() {
        const RAW_ISSUER_CANARY: &str = "https://issuer-canary.invalid/private";
        const JWT_CANARY: &str = "eyJ.synthetic.jwt.canary";
        const PRIVATE_DISPLAY_CANARY: &str = "private-display-claim-canary";
        const JWKS_CANARY: &str = "{\"keys\":[{\"kid\":\"private-jwks-canary\"}]}";
        let fixture = IsolatedPostgres::migrated("operator").await;
        let domain = CommunityId::from_uuid(Uuid::new_v4());
        let binding_id = Uuid::new_v4();
        sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
            .bind(domain.as_uuid())
            .bind(format!("{}.operator.o5.test", domain.as_uuid()))
            .execute(&fixture.pool)
            .await
            .expect("insert synthetic operator domain");
        sqlx::query(
            "INSERT INTO identity_bindings \
             (community_id,issuer,uid,pubkey,display_name,source,binding_id, \
              creation_attribution_kind) \
             VALUES ($1,$2,$3,$4,$5,'db_binding',$6,'legacy_unknown')",
        )
        .bind(domain.as_uuid())
        .bind(RAW_ISSUER_CANARY)
        .bind(JWT_CANARY)
        .bind([31_u8; 32].as_slice())
        .bind(format!("{PRIVATE_DISPLAY_CANARY}:{JWKS_CANARY}"))
        .bind(binding_id)
        .execute(&fixture.pool)
        .await
        .expect("insert synthetic active binding");

        let reference_key = OperatorReferenceKey::new([41; 32], 1).unwrap();
        let pseudonymizer =
            Pseudonymizer::new(PseudonymKey::new([51; 32]).expect("pseudonym key"), 1);
        let list = OperatorLifecycleCommand {
            domain,
            operation_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            semantic_fingerprint: [61; 32],
            expected_revision: 1,
            action: OperatorLifecycleAction::List,
            reason_code: 3,
            target_reference: None,
            target_pseudonym: None,
            replacement_reference: None,
            replacement: None,
            list_limit: 10,
            list_after: None,
            authority: authority(&pseudonymizer, domain, [71; 32], None),
        };
        let listed = fixture
            .db
            .execute_operator_lifecycle(&reference_key, &list)
            .await
            .expect("list through durable operator executor");
        assert_eq!(listed.status, OperatorLifecycleStatus::Listed);
        assert_eq!(listed.records.len(), 1);
        let target = listed.records[0].reference;
        let target_pseudonym = pseudonymizer
            .derive(domain, ReferenceKind::Binding, &target)
            .unwrap();

        sqlx::query(
            "UPDATE authorization_evidence_capacity_state \
             SET restrictive_remaining=0 WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .execute(&fixture.pool)
        .await
        .expect("exhaust restrictive audit capacity");
        let unavailable_audit = OperatorLifecycleCommand {
            domain,
            operation_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            semantic_fingerprint: [80; 32],
            expected_revision: 1,
            action: OperatorLifecycleAction::Revoke,
            reason_code: 2,
            target_reference: Some(target),
            target_pseudonym: Some(target_pseudonym),
            replacement_reference: None,
            replacement: None,
            list_limit: 1,
            list_after: None,
            authority: authority(&pseudonymizer, domain, [70; 32], Some([90; 32])),
        };
        assert!(matches!(
            fixture
                .db
                .execute_operator_lifecycle(&reference_key, &unavailable_audit)
                .await,
            Err(OperatorLifecycleFailure::Storage(_))
        ));
        let unchanged_state: String = sqlx::query_scalar(
            "SELECT binding_state FROM identity_bindings WHERE community_id=$1 AND binding_id=$2",
        )
        .bind(domain.as_uuid())
        .bind(binding_id)
        .fetch_one(&fixture.pool)
        .await
        .expect("inspect rollback after audit failure");
        assert_eq!(unchanged_state, "active");
        let failed_receipt_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM authorization_operator_operation_receipts \
             WHERE community_id=$1 AND operation_id=$2",
        )
        .bind(domain.as_uuid())
        .bind(unavailable_audit.operation_id)
        .fetch_one(&fixture.pool)
        .await
        .expect("audit failure leaves no success receipt");
        assert_eq!(failed_receipt_count, 0);
        sqlx::query(
            "UPDATE authorization_evidence_capacity_state \
             SET restrictive_remaining=10000 WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .execute(&fixture.pool)
        .await
        .expect("restore synthetic restrictive capacity");

        let revoke_a = OperatorLifecycleCommand {
            domain,
            operation_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            semantic_fingerprint: [81; 32],
            expected_revision: 1,
            action: OperatorLifecycleAction::Revoke,
            reason_code: 1,
            target_reference: Some(target),
            target_pseudonym: Some(target_pseudonym),
            replacement_reference: None,
            replacement: None,
            list_limit: 1,
            list_after: None,
            authority: authority(&pseudonymizer, domain, [72; 32], Some([91; 32])),
        };
        let revoke_b = OperatorLifecycleCommand {
            domain,
            operation_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            semantic_fingerprint: [82; 32],
            expected_revision: 1,
            action: OperatorLifecycleAction::Revoke,
            reason_code: 1,
            target_reference: Some(target),
            target_pseudonym: Some(target_pseudonym),
            replacement_reference: None,
            replacement: None,
            list_limit: 1,
            list_after: None,
            authority: authority(&pseudonymizer, domain, [73; 32], Some([92; 32])),
        };
        let (first, second) = tokio::join!(
            fixture
                .db
                .execute_operator_lifecycle(&reference_key, &revoke_a),
            fixture
                .db
                .execute_operator_lifecycle(&reference_key, &revoke_b),
        );
        let successes = [&first, &second]
            .into_iter()
            .filter(|result| result.is_ok())
            .count();
        let stale_denials = [&first, &second]
            .into_iter()
            .filter(|result| {
                matches!(
                    result,
                    Err(OperatorLifecycleFailure::Denied(
                        DecisionReason::StaleExpectedState
                    ))
                )
            })
            .count();
        assert_eq!(successes, 1, "exactly one concurrent revoke commits");
        assert_eq!(stale_denials, 1, "the stale contender is durably denied");

        let winner = if first.is_ok() { &revoke_a } else { &revoke_b };
        let replay = fixture
            .db
            .execute_operator_lifecycle(&reference_key, winner)
            .await
            .expect("exact operation replay returns original result");
        assert_eq!(replay.status, OperatorLifecycleStatus::Revoked);
        assert_eq!(replay.lifecycle_revision, 2);

        let mut replayed_authority = authority(&pseudonymizer, domain, [74; 32], None);
        replayed_authority.evidence_id = winner.authority.evidence_id;
        let replayed_authority_command = OperatorLifecycleCommand {
            domain,
            operation_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            semantic_fingerprint: [84; 32],
            expected_revision: 2,
            action: OperatorLifecycleAction::List,
            reason_code: 3,
            target_reference: None,
            target_pseudonym: None,
            replacement_reference: None,
            replacement: None,
            list_limit: 10,
            list_after: None,
            authority: replayed_authority,
        };
        assert!(matches!(
            fixture
                .db
                .execute_operator_lifecycle(&reference_key, &replayed_authority_command)
                .await,
            Err(OperatorLifecycleFailure::Denied(
                DecisionReason::EvidenceReplayed
            ))
        ));

        let state: (String, i64, String) = sqlx::query_as(
            "SELECT binding_state,binding_version,revocation_scope FROM identity_bindings \
             WHERE community_id=$1 AND binding_id=$2",
        )
        .bind(domain.as_uuid())
        .bind(binding_id)
        .fetch_one(&fixture.pool)
        .await
        .expect("inspect revoked binding");
        assert_eq!(state, ("revoked".into(), 2, "key".into()));
        let receipt_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM authorization_operator_operation_receipts WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .fetch_one(&fixture.pool)
        .await
        .expect("count operator receipts");
        let effect_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM authorization_operator_effects WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .fetch_one(&fixture.pool)
        .await
        .expect("count operator effects");
        let outbox_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM authorization_audit_outbox WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .fetch_one(&fixture.pool)
        .await
        .expect("count operator audit events");
        assert_eq!(
            receipt_count, 4,
            "list, winner, stale denial, and replay denial all have receipts"
        );
        assert_eq!(effect_count, 1, "one revoke effect commits");
        assert_eq!(
            outbox_count, 4,
            "every operator result is atomically audited"
        );
        let invalidation_receipts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM authorization_invalidation_receipts WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .fetch_one(&fixture.pool)
        .await
        .expect("count atomic invalidation receipts");
        let invalidation_floors: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM authorization_invalidation_floors \
             WHERE community_id=$1 AND generation=1",
        )
        .bind(domain.as_uuid())
        .fetch_one(&fixture.pool)
        .await
        .expect("count exact invalidation floors");
        assert_eq!(
            invalidation_receipts, 1,
            "one committed mutation invalidates"
        );
        assert_eq!(
            invalidation_floors, 2,
            "binding floor and domain fence commit atomically"
        );

        let self_approved = OperatorLifecycleCommand {
            domain,
            operation_id: Uuid::new_v4(),
            correlation_id: Uuid::new_v4(),
            semantic_fingerprint: [83; 32],
            expected_revision: 2,
            action: OperatorLifecycleAction::Revoke,
            reason_code: 2,
            target_reference: Some(target),
            target_pseudonym: Some(target_pseudonym),
            replacement_reference: None,
            replacement: None,
            list_limit: 1,
            list_after: None,
            authority: authority(&pseudonymizer, domain, [93; 32], Some([93; 32])),
        };
        assert!(matches!(
            fixture
                .db
                .execute_operator_lifecycle(&reference_key, &self_approved)
                .await,
            Err(OperatorLifecycleFailure::Denied(
                DecisionReason::SelfApproval
            ))
        ));
        let state_after_denial: String = sqlx::query_scalar(
            "SELECT binding_state FROM identity_bindings WHERE community_id=$1 AND binding_id=$2",
        )
        .bind(domain.as_uuid())
        .bind(binding_id)
        .fetch_one(&fixture.pool)
        .await
        .expect("self-approval cannot mutate binding");
        assert_eq!(state_after_denial, "revoked");

        let exporter = ExporterId::generate();
        let lease = fixture
            .db
            .claim_authorization_delivery(
                domain,
                DeliveryKind::AuditOutbox,
                exporter,
                Duration::from_secs(30),
            )
            .await
            .expect("claim operator audit export")
            .expect("operator audit lease");
        fixture
            .db
            .fail_authorization_delivery(
                domain,
                DeliveryKind::AuditOutbox,
                lease.event_id(),
                lease.delivery_attempt_id(),
                DeliveryDisposition::Quarantine(ControlCode::PoisonEvent),
                RetryPolicy::new(Duration::from_millis(1), Duration::from_secs(1), 3)
                    .expect("bounded retry policy"),
            )
            .await
            .expect("dead-letter synthetic operator export");
        let canonical_events: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT canonical_event FROM authorization_audit_outbox WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .fetch_all(&fixture.pool)
        .await
        .expect("read immutable operator audit bytes");
        assert_eq!(
            canonical_events.len(),
            5,
            "all operator outcomes are present"
        );
        let dead_letters: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM authorization_evidence_dead_letters \
             WHERE community_id=$1 AND audit_event_id=$2",
        )
        .bind(domain.as_uuid())
        .bind(lease.event_id().as_uuid())
        .fetch_one(&fixture.pool)
        .await
        .expect("read synthetic operator dead letter");
        assert_eq!(dead_letters, 1);
        let dead_letter_projections: Vec<String> = sqlx::query_scalar(
            "SELECT to_jsonb(dead_letter)::text FROM authorization_evidence_dead_letters dead_letter \
             WHERE community_id=$1",
        )
        .bind(domain.as_uuid())
        .fetch_all(&fixture.pool)
        .await
        .expect("read bounded dead-letter projections");
        for canary in [
            RAW_ISSUER_CANARY,
            JWT_CANARY,
            PRIVATE_DISPLAY_CANARY,
            JWKS_CANARY,
        ] {
            assert!(
                !lease
                    .canonical_event()
                    .windows(canary.len())
                    .any(|window| window == canary.as_bytes()),
                "raw identity canary crossed the export lease"
            );
            assert!(
                canonical_events.iter().all(|event| !event
                    .windows(canary.len())
                    .any(|window| window == canary.as_bytes())),
                "raw identity canary crossed durable audit"
            );
            assert!(
                dead_letter_projections
                    .iter()
                    .all(|projection| !projection.contains(canary)),
                "raw identity canary crossed dead-letter evidence"
            );
        }

        assert!(
            sqlx::query(
                "UPDATE authorization_operator_operation_receipts \
                 SET affected_count=99 WHERE community_id=$1"
            )
            .bind(domain.as_uuid())
            .execute(&fixture.pool)
            .await
            .is_err(),
            "immutable operator receipts reject row tampering"
        );
        assert!(
            sqlx::query("TRUNCATE authorization_operator_effects")
                .execute(&fixture.pool)
                .await
                .is_err(),
            "immutable operator effects reject truncation"
        );
        assert!(
            sqlx::query("TRUNCATE authorization_lifecycle_previews")
                .execute(&fixture.pool)
                .await
                .is_err(),
            "immutable previews reject truncation"
        );

        fixture.cleanup().await;
    }
}
