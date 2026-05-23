//! Iroh-based SV2 transport.
//!
//! This module provides an alternative transport for SV2 connections built on
//! iroh's QUIC + raw-public-key TLS + relay-fallback stack, while preserving
//! the SV2 Noise NX handshake (run inside the iroh bidi stream).
//!
//! Phase 1 ships only the minimal surface needed to prove a Noise-on-iroh
//! frame round-trips end-to-end:
//!
//! - [`alpn`]: per-role ALPN constants (`sv2/pool/0`, etc.).
//! - [`duplex`]: glues iroh's split [`iroh::endpoint::SendStream`] /
//!   [`iroh::endpoint::RecvStream`] into a single
//!   [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`] type.
//! - [`noise_iroh_stream`]: type alias for
//!   [`crate::network_helpers::noise_generic_stream::NoiseGenericStream`]
//!   over [`duplex::IrohDuplex`].
//!
//! Wave 2 will add admission, identity, discovery, endpoint, connector,
//! listener, connection, and metrics submodules. See
//! `/Users/garykrause/.claude/plans/how-might-we-implement-snoopy-lollipop.md`
//! for the full design.

pub mod admission;
pub mod alpn;
pub mod config;
pub mod connection;
pub mod connector;
pub mod discovery;
pub mod duplex;
pub mod endpoint;
pub mod identity;
pub mod listener;
pub mod noise_iroh_stream;

#[cfg(feature = "iroh-transport-monitoring")]
pub mod metrics;

// Per-role TOML config. Re-exported at the iroh module surface so role configs
// can `use crate::network_helpers::iroh::IrohRoleConfig` without reaching into
// the `config` submodule directly.
pub use config::{
    AdmissionConfig, AdmissionMode, IrohConfigError, IrohRoleConfig, ResolvedIrohRoleConfig,
};

// Re-export the most commonly used iroh public types so role apps that depend
// on stratum-apps (with `iroh-transport` enabled) do not need to take a direct
// `iroh = "..."` dependency just to name an `Endpoint` or `EndpointId`. Only the
// types actually crossed at the role/library boundary are surfaced here.
pub use ::iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
