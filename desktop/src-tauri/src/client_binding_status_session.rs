//! Native-only relay binding status validation and projection.

use std::fmt;

use buzz_core_pkg::{
    client_binding_bootstrap::{
        validate_client_binding_bootstrap_event, ClientBindingEpoch,
        CLIENT_BINDING_BOOTSTRAP_SUB_ID, CLIENT_BINDING_STATUS_SUB_ID,
    },
    client_binding_status::{ClientBindingStatusTracker, ClientBindingStatusUpdate},
    verify_event,
};
use nostr::{Event, EventId, PublicKey};
use serde::Serialize;
use serde_json::Value;

/// Current-only data permitted to cross the native IPC boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CurrentProjection {
    pub(crate) event_author_pubkey: String,
    pub(crate) fresh_until: u64,
    pub(crate) connection_epoch: String,
}

/// One change produced by the serialized native fold.
pub(crate) enum ProjectionUpdate {
    Unchanged,
    Clear,
    Current(CurrentProjection),
}

struct ReservedEvent {
    event: Result<Event, ()>,
    exact_outer_shape: bool,
}

enum ReservedFrame {
    Bootstrap(ReservedEvent),
    Status(ReservedEvent),
}

/// Connection-scoped wrapper around the shared authenticated status tracker.
pub(crate) struct ClientBindingStatusSession {
    trusted_relay_pubkey: PublicKey,
    expected_event_author_pubkey: PublicKey,
    connection_epoch: ClientBindingEpoch,
    bootstrap_event_id: Option<EventId>,
    bootstrap_latched_invalid: bool,
    tracker: Option<ClientBindingStatusTracker>,
    projected_fresh_until: Option<u64>,
}

impl fmt::Debug for ClientBindingStatusSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientBindingStatusSession")
            .field("trusted_relay_pubkey", &"[redacted]")
            .field("expected_event_author_pubkey", &"[redacted]")
            .field("connection_epoch", &"[redacted]")
            .field(
                "bootstrap_event_id",
                &self.bootstrap_event_id.map(|_| "[redacted]"),
            )
            .field("bootstrap_latched_invalid", &self.bootstrap_latched_invalid)
            .field("tracker", &self.tracker.as_ref().map(|_| "[redacted]"))
            .field("projected_fresh_until", &"[redacted]")
            .finish()
    }
}

impl ClientBindingStatusSession {
    pub(crate) fn new(
        trusted_relay_pubkey: PublicKey,
        expected_event_author_pubkey: PublicKey,
        connection_epoch: ClientBindingEpoch,
    ) -> Self {
        Self {
            trusted_relay_pubkey,
            expected_event_author_pubkey,
            connection_epoch,
            bootstrap_event_id: None,
            bootstrap_latched_invalid: false,
            tracker: None,
            projected_fresh_until: None,
        }
    }

    pub(crate) fn connection_epoch(&self) -> &ClientBindingEpoch {
        &self.connection_epoch
    }

    /// Swallow and fold an exact reserved EVENT frame. All other frames return
    /// `None` and must be delivered to the webview unchanged.
    pub(crate) fn consume_text(&mut self, text: &str, now: u64) -> Option<ProjectionUpdate> {
        let frame = reserved_frame(text.as_bytes())?;
        Some(match frame {
            ReservedFrame::Bootstrap(event) => self.accept_bootstrap(event, now),
            ReservedFrame::Status(event) => self.accept_status(event, now),
        })
    }

    pub(crate) fn projected_fresh_until(&self) -> Option<u64> {
        self.projected_fresh_until
    }

    pub(crate) fn expire(&mut self, now: u64) -> ProjectionUpdate {
        let expired = self
            .projected_fresh_until
            .is_some_and(|fresh_until| now >= fresh_until);
        if !expired {
            return ProjectionUpdate::Unchanged;
        }
        if let Some(tracker) = self.tracker.as_mut() {
            let _ = tracker.current_presentation(now);
        }
        self.projected_fresh_until = None;
        ProjectionUpdate::Clear
    }

    pub(crate) fn disconnect(&mut self) -> ProjectionUpdate {
        if let Some(tracker) = self.tracker.as_mut() {
            tracker.on_disconnect();
        }
        self.projected_fresh_until = None;
        ProjectionUpdate::Clear
    }

    fn accept_bootstrap(&mut self, reserved: ReservedEvent, now: u64) -> ProjectionUpdate {
        let Ok(event) = reserved.event else {
            return ProjectionUpdate::Unchanged;
        };
        if verify_event(&event).is_err() || event.pubkey != self.trusted_relay_pubkey {
            return ProjectionUpdate::Unchanged;
        }
        if !reserved.exact_outer_shape || self.bootstrap_latched_invalid {
            self.bootstrap_latched_invalid = true;
            return self.clear_trusted_invalid();
        }
        let bootstrap = match validate_client_binding_bootstrap_event(
            &event,
            &self.trusted_relay_pubkey,
            &self.connection_epoch,
            &self.expected_event_author_pubkey,
            now,
        ) {
            Ok(bootstrap) => bootstrap,
            Err(_) => {
                self.bootstrap_latched_invalid = true;
                return self.clear_trusted_invalid();
            }
        };
        if let Some(event_id) = self.bootstrap_event_id {
            return if event_id == event.id {
                ProjectionUpdate::Unchanged
            } else {
                self.bootstrap_latched_invalid = true;
                self.clear_trusted_invalid()
            };
        }
        self.bootstrap_event_id = Some(event.id);
        self.tracker = Some(ClientBindingStatusTracker::new(
            self.trusted_relay_pubkey,
            bootstrap.authorization_domain(),
            self.expected_event_author_pubkey,
        ));
        ProjectionUpdate::Unchanged
    }

    fn accept_status(&mut self, reserved: ReservedEvent, now: u64) -> ProjectionUpdate {
        let Ok(event) = reserved.event else {
            return ProjectionUpdate::Unchanged;
        };
        if verify_event(&event).is_err() || event.pubkey != self.trusted_relay_pubkey {
            return ProjectionUpdate::Unchanged;
        }
        if self.bootstrap_latched_invalid {
            return self.clear_trusted_invalid();
        }
        if !reserved.exact_outer_shape {
            if self.tracker.is_none() {
                self.bootstrap_latched_invalid = true;
            }
            return self.clear_trusted_invalid();
        }
        let Some(tracker) = self.tracker.as_mut() else {
            self.bootstrap_latched_invalid = true;
            return self.clear_trusted_invalid();
        };
        match tracker.accept(&event, now) {
            Ok(ClientBindingStatusUpdate::Duplicate) => ProjectionUpdate::Unchanged,
            Ok(ClientBindingStatusUpdate::Accepted) => {
                let Some(status) = tracker.current_presentation(now) else {
                    self.projected_fresh_until = None;
                    return ProjectionUpdate::Clear;
                };
                self.projected_fresh_until = Some(status.fresh_until());
                ProjectionUpdate::Current(CurrentProjection {
                    event_author_pubkey: self.expected_event_author_pubkey.to_hex(),
                    fresh_until: status.fresh_until(),
                    connection_epoch: self.connection_epoch.as_str().to_owned(),
                })
            }
            Err(_) => self.clear_trusted_invalid(),
        }
    }

    fn clear_trusted_invalid(&mut self) -> ProjectionUpdate {
        self.projected_fresh_until = None;
        ProjectionUpdate::Clear
    }
}

fn reserved_frame(bytes: &[u8]) -> Option<ReservedFrame> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let values = value.as_array()?;
    if values.first().and_then(Value::as_str) != Some("EVENT") {
        return None;
    }
    let reserved = match values.get(1).and_then(Value::as_str) {
        Some(CLIENT_BINDING_BOOTSTRAP_SUB_ID) => ReservedFrame::Bootstrap,
        Some(CLIENT_BINDING_STATUS_SUB_ID) => ReservedFrame::Status,
        _ => return None,
    };
    let event = values
        .get(2)
        .cloned()
        .ok_or(())
        .and_then(|value| serde_json::from_value(value).map_err(|_| ()));
    Some(reserved(ReservedEvent {
        event,
        exact_outer_shape: values.len() == 3,
    }))
}

/// Classify the reserved exact-connection channels without requiring an
/// eligible presentation session. Every native socket uses this to prevent
/// bootstrap and status frames from reaching raw browser delivery.
pub(crate) fn is_reserved_text(text: &str) -> bool {
    reserved_frame(text.as_bytes()).is_some()
}
