//! Duplex wrapper over iroh's split [`SendStream`] / [`RecvStream`] so they
//! can be used together as a single [`AsyncRead`] + [`AsyncWrite`] type.
//!
//! This lets us drop an iroh bidi stream straight into
//! [`crate::network_helpers::noise_generic_stream::NoiseGenericStream`]
//! without forcing the Noise pump to know anything about iroh.
//!
//! Both halves already implement the relevant tokio traits in iroh 0.91+;
//! `IrohDuplex` is a thin glue type that forwards `poll_read` to the recv
//! half and `poll_write` / `poll_flush` / `poll_shutdown` to the send half.

use std::pin::Pin;
use std::task::{Context, Poll};

use iroh::endpoint::{RecvStream, SendStream};
use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite, ReadBuf};

/// A bidirectional stream backed by an iroh QUIC bidi pair.
///
/// The send and recv halves are independent in iroh; this type bundles them
/// so generic transport code (Noise pumps, tokio combinators) can treat the
/// pair as a single `AsyncRead + AsyncWrite + Unpin + Send` value.
pub struct IrohDuplex {
    /// Outbound (write) half of the iroh bidi stream.
    pub send: SendStream,
    /// Inbound (read) half of the iroh bidi stream.
    pub recv: RecvStream,
}

impl TokioAsyncRead for IrohDuplex {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Disambiguate against the inherent `RecvStream::poll_read` method
        // that returns iroh's own error type.
        TokioAsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}

impl TokioAsyncWrite for IrohDuplex {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        // Disambiguate against the inherent `SendStream::poll_write` method
        // that returns `iroh::endpoint::WriteError`.
        TokioAsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        TokioAsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        TokioAsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}
