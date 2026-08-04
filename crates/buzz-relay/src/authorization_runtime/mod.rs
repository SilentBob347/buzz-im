//! Provider-neutral authorization interfaces available before runtime installation.

/// Activation and enrollment types consumed by protected transports.
pub mod finalization;
/// Protected transport authorization and lease fencing.
pub mod transport;
