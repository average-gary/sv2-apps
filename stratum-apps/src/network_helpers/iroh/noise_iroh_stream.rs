//! `NoiseIrohStream`: SV2 Noise NX over an iroh QUIC bidi stream.
//!
//! This is a thin type alias on top of
//! [`crate::network_helpers::noise_generic_stream::NoiseGenericStream`]
//! parameterized over [`crate::network_helpers::iroh::duplex::IrohDuplex`].
//! All the Noise pump logic lives in the generic stream; this file exists
//! so call-sites can write `NoiseIrohStream<AnyMessage<'static>>` instead
//! of spelling out the full generic instantiation.

use crate::network_helpers::iroh::duplex::IrohDuplex;
use crate::network_helpers::noise_generic_stream::NoiseGenericStream;

/// Convenience alias: a Noise-encrypted SV2 stream running over an iroh
/// QUIC bidi pair.
pub type NoiseIrohStream<Message> = NoiseGenericStream<IrohDuplex, Message>;
