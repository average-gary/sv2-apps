//! Generic Noise-encrypted stream layer over any `AsyncRead + AsyncWrite` transport.
//!
//! This is a sibling of [`noise_stream`](super::noise_stream) — same Noise NX
//! handshake, same frame pump, same `read_frame` / `write_frame` API surface,
//! but generic over the underlying byte transport instead of being concretely
//! typed on `tokio::net::TcpStream`. It exists so additional transports
//! (anything that already implements `tokio::io::AsyncRead + AsyncWrite`)
//! can reuse the SV2 Noise handshake without forking 200 lines of state-machine
//! pump logic.
//!
//! # Why a sibling and not a generic refactor of `noise_stream.rs`?
//!
//! Generalizing `noise_stream.rs` in place is the cleaner-code option: the
//! `NoiseTcpStream<M>` type would become `NoiseStream<TcpStream, M>` (a type
//! alias) and the body would be unchanged. We chose the sibling-file approach
//! to keep `noise_stream.rs` at zero diff against upstream `main`. This means
//! ongoing PRs that touch the existing TCP+Noise pump (bug fixes, perf work,
//! cancellation-safety patches) won't conflict with this PR or with downstream
//! work that builds on top of the generic stream type. The duplicated
//! ~150 LOC is the explicit trade.
//!
//! If reviewers prefer the in-place generalization, switching is mechanical:
//! delete this file and rename `NoiseTcpStream`'s impl to `NoiseStream<S, M>`.
//!
//! # When to use this type
//!
//! Use [`NoiseGenericStream`] when adding a new SV2 transport whose underlying
//! byte stream type is not `tokio::net::TcpStream`. Today there is no such
//! consumer in this repo — this type is laying groundwork for the iroh QUIC
//! transport tracked in [SRI Discussion #1935][1].
//!
//! [1]: https://github.com/stratum-mining/stratum/discussions/1935

use std::time::Duration;

use crate::network_helpers::Error;
use stratum_core::{
    binary_sv2::{Deserialize, GetSize, Serialize},
    codec_sv2::{HandshakeRole, NoiseEncoder, StandardEitherFrame, StandardNoiseDecoder, State},
    framing_sv2::framing::HandShakeFrame,
    noise_sv2::{ELLSWIFT_ENCODING_SIZE, INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tracing::{debug, error};

/// A Noise-secured duplex stream that wraps any `AsyncRead + AsyncWrite + Unpin + Send`
/// transport and provides secure read/write capabilities using the Noise protocol.
///
/// This stream performs the full Noise handshake during construction and returns
/// a bidirectional encrypted stream split into read and write halves.
///
/// **Note:** This struct is **not cancellation-safe**. If `read_frame()` or
/// `write_frame()` is canceled mid-way, internal state may be left in an
/// inconsistent state, which can lead to protocol errors or dropped frames.
pub struct NoiseGenericStream<S, Message>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    Message: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    reader: NoiseGenericReadHalf<S, Message>,
    writer: NoiseGenericWriteHalf<S, Message>,
}

/// The reading half of a [`NoiseGenericStream`].
///
/// It buffers incoming encrypted bytes, attempts to decode full Noise frames,
/// and exposes a method to retrieve structured messages of type `Message`.
pub struct NoiseGenericReadHalf<S, Message>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    Message: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    reader: ReadHalf<S>,
    decoder: StandardNoiseDecoder<Message>,
    state: State,
    current_frame_buf: Vec<u8>,
    bytes_read: usize,
}

/// The writing half of a [`NoiseGenericStream`].
///
/// It accepts structured messages, encodes them via the Noise protocol,
/// and writes the result to the underlying transport.
pub struct NoiseGenericWriteHalf<S, Message>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    Message: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    writer: WriteHalf<S>,
    encoder: NoiseEncoder<Message>,
    state: State,
}

impl<S, Message> NoiseGenericStream<S, Message>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    Message: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    /// Constructs a new `NoiseGenericStream` over the given transport,
    /// performing the Noise handshake in the given `role`.
    ///
    /// On success, returns a stream with encrypted communication channels.
    ///
    /// `timeout` applies to each individual handshake read.
    pub async fn new(stream: S, role: HandshakeRole, timeout: Duration) -> Result<Self, Error> {
        let (mut reader, mut writer) = tokio::io::split(stream);

        let mut decoder = StandardNoiseDecoder::<Message>::new();
        let mut encoder = NoiseEncoder::<Message>::new();
        let mut state = State::initialized(role.clone());

        match role {
            HandshakeRole::Initiator(_) => {
                let mut responder_state = State::not_initialized(&role);
                let first_msg = state.step_0()?;
                send_message(&mut writer, first_msg.into(), &mut state, &mut encoder).await?;
                debug!("First handshake message sent");

                loop {
                    match receive_message(&mut reader, &mut responder_state, &mut decoder, timeout)
                        .await
                    {
                        Ok(second_msg) => {
                            debug!("Second handshake message received");
                            let handshake_frame: HandShakeFrame = second_msg
                                .try_into()
                                .map_err(|_| Error::HandshakeRemoteInvalidMessage)?;
                            let payload: [u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE] =
                                handshake_frame
                                    .get_payload_when_handshaking()
                                    .try_into()
                                    .map_err(|_| Error::HandshakeRemoteInvalidMessage)?;
                            let transport_state = state.step_2(payload)?;
                            state = transport_state;
                            break;
                        }
                        Err(Error::CodecError(stratum_core::codec_sv2::Error::MissingBytes(_))) => {
                            debug!("Waiting for more bytes during handshake");
                        }
                        Err(e) => {
                            error!("Handshake failed with upstream: {:?}", e);
                            return Err(e);
                        }
                    }
                }
            }
            HandshakeRole::Responder(_) => {
                let mut initiator_state = State::not_initialized(&role);

                loop {
                    match receive_message(&mut reader, &mut initiator_state, &mut decoder, timeout)
                        .await
                    {
                        Ok(first_msg) => {
                            debug!("First handshake message received");
                            let handshake_frame: HandShakeFrame = first_msg
                                .try_into()
                                .map_err(|_| Error::HandshakeRemoteInvalidMessage)?;
                            let payload: [u8; ELLSWIFT_ENCODING_SIZE] = handshake_frame
                                .get_payload_when_handshaking()
                                .try_into()
                                .map_err(|_| Error::HandshakeRemoteInvalidMessage)?;
                            let (second_msg, transport_state) = state.step_1(payload)?;
                            send_message(&mut writer, second_msg.into(), &mut state, &mut encoder)
                                .await?;
                            debug!("Second handshake message sent");
                            state = transport_state;
                            break;
                        }
                        Err(Error::CodecError(stratum_core::codec_sv2::Error::MissingBytes(_))) => {
                            debug!("Waiting for more bytes during handshake");
                        }
                        Err(e) => {
                            error!("Handshake failed with downstream: {:?}", e);
                            return Err(e);
                        }
                    }
                }
            }
        };
        Ok(Self {
            reader: NoiseGenericReadHalf {
                reader,
                decoder,
                state: state.clone(),
                current_frame_buf: vec![],
                bytes_read: 0,
            },
            writer: NoiseGenericWriteHalf {
                writer,
                encoder,
                state,
            },
        })
    }

    /// Consumes the stream and returns its reader and writer halves.
    pub fn into_split(
        self,
    ) -> (
        NoiseGenericReadHalf<S, Message>,
        NoiseGenericWriteHalf<S, Message>,
    ) {
        (self.reader, self.writer)
    }
}

impl<S, Message> NoiseGenericWriteHalf<S, Message>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    Message: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    /// Encrypts and writes a full message frame to the transport.
    ///
    /// Returns an error if the transport is closed or the message cannot be encoded.
    ///
    /// Not cancellation-safe: A canceled write may cause partial writes or state corruption.
    pub async fn write_frame(&mut self, frame: StandardEitherFrame<Message>) -> Result<(), Error> {
        let buf = self.encoder.encode(frame, &mut self.state)?;
        self.writer
            .write_all(buf.as_ref())
            .await
            .map_err(|_| Error::SocketClosed)?;
        Ok(())
    }

    /// Gracefully shuts down the writing half of the stream.
    ///
    /// Returns an error if the shutdown fails.
    pub async fn shutdown(&mut self) -> Result<(), Error> {
        self.writer
            .shutdown()
            .await
            .map_err(|_| Error::SocketClosed)
    }
}

impl<S, Message> NoiseGenericReadHalf<S, Message>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    Message: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    /// Reads and decodes a complete frame from the transport.
    ///
    /// This method blocks until a full frame is read and decoded,
    /// handling `MissingBytes` errors from the codec automatically.
    ///
    /// Not cancellation-safe: Cancellation may leave partially-read state behind.
    pub async fn read_frame(&mut self) -> Result<StandardEitherFrame<Message>, Error> {
        loop {
            let expected = self.decoder.writable_len();

            if self.current_frame_buf.len() != expected {
                self.current_frame_buf.resize(expected, 0);
                self.bytes_read = 0;
            }

            while self.bytes_read < expected {
                let n = self
                    .reader
                    .read(&mut self.current_frame_buf[self.bytes_read..])
                    .await
                    .map_err(|_| Error::SocketClosed)?;

                if n == 0 {
                    return Err(Error::SocketClosed);
                }

                self.bytes_read += n;
            }

            self.decoder
                .writable()
                .copy_from_slice(&self.current_frame_buf[..]);

            self.bytes_read = 0;

            match self.decoder.next_frame(&mut self.state) {
                Ok(frame) => return Ok(frame),
                Err(stratum_core::codec_sv2::Error::MissingBytes(_)) => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(e) => return Err(Error::CodecError(e)),
            }
        }
    }
}

async fn send_message<W, Message>(
    writer: &mut W,
    msg: StandardEitherFrame<Message>,
    state: &mut State,
    encoder: &mut NoiseEncoder<Message>,
) -> Result<(), Error>
where
    W: AsyncWrite + Unpin + Send,
    Message: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    let buffer = encoder.encode(msg, state)?;
    writer
        .write_all(buffer.as_ref())
        .await
        .map_err(|_| Error::SocketClosed)?;
    Ok(())
}

async fn receive_message<R, Message>(
    reader: &mut R,
    state: &mut State,
    decoder: &mut StandardNoiseDecoder<Message>,
    timeout: Duration,
) -> Result<StandardEitherFrame<Message>, Error>
where
    R: AsyncRead + Unpin + Send,
    Message: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    let mut buffer = vec![0u8; decoder.writable_len()];
    tokio::time::timeout(timeout, reader.read_exact(&mut buffer))
        .await
        .map_err(|_| Error::HandshakeTimeout)?
        .map_err(|_| Error::SocketClosed)?;
    decoder.writable().copy_from_slice(&buffer);
    decoder.next_frame(state).map_err(Error::CodecError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
    use stratum_core::{
        binary_sv2::{Str0255, B0255},
        codec_sv2::{HandshakeRole, StandardEitherFrame},
        common_messages_sv2::{Protocol, SetupConnection},
        framing_sv2::framing::Sv2Frame,
        noise_sv2::{Initiator, Responder},
        parsers_sv2::{AnyMessage, CommonMessages},
    };

    /// Authority keypair used by the existing integration-tests fixtures
    /// (matches `integration-tests/lib/utils.rs`).
    const TEST_PUB_KEY: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
    const TEST_PRV_KEY: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";

    fn build_responder() -> Box<Responder> {
        let pub_key = TEST_PUB_KEY
            .parse::<Secp256k1PublicKey>()
            .unwrap()
            .into_bytes();
        let prv_key = TEST_PRV_KEY
            .parse::<Secp256k1SecretKey>()
            .unwrap()
            .into_bytes();
        Responder::from_authority_kp(&pub_key, &prv_key, Duration::from_secs(10_000)).unwrap()
    }

    fn build_initiator() -> Box<Initiator> {
        let pub_key = TEST_PUB_KEY
            .parse::<Secp256k1PublicKey>()
            .unwrap()
            .into_bytes();
        Initiator::from_raw_k(pub_key).unwrap()
    }

    /// Build a `SetupConnection` test message and return both:
    /// - a [`StandardEitherFrame`] suitable to hand to `write_frame`, and
    /// - the SV2-serialized payload bytes that we expect to see on the
    ///   receiving end after Noise decryption + frame decoding.
    fn build_setup_connection_frame() -> (StandardEitherFrame<AnyMessage<'static>>, Vec<u8>) {
        use stratum_core::parsers_sv2::IsSv2Message;

        let endpoint_host: B0255 = "0.0.0.0".to_string().into_bytes().try_into().unwrap();
        let vendor: Str0255 = "test".to_string().try_into().unwrap();
        let hardware_version: Str0255 = "test".to_string().try_into().unwrap();
        let firmware: Str0255 = "test".to_string().try_into().unwrap();
        let device_id: Str0255 = "test".to_string().try_into().unwrap();

        let setup = SetupConnection {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: 0,
            endpoint_host,
            endpoint_port: 0,
            vendor,
            hardware_version,
            firmware,
            device_id,
        };
        // Serialize the message ourselves so we have a stable byte vector to
        // compare against after the round-trip. `binary_sv2::to_bytes` produces
        // exactly the wire payload that the decoder will hand back to us.
        let expected_payload =
            stratum_core::binary_sv2::to_bytes(setup.clone()).expect("encode SetupConnection");

        let any: AnyMessage<'static> = AnyMessage::Common(CommonMessages::SetupConnection(setup));
        let message_type = any.message_type();
        let sv2_frame: Sv2Frame<AnyMessage<'static>, _> =
            Sv2Frame::from_message(any, message_type, 0, false)
                .expect("Failed to create SetupConnection frame");
        let either: StandardEitherFrame<AnyMessage<'static>> = StandardEitherFrame::Sv2(sv2_frame);
        (either, expected_payload)
    }

    /// Extract the serialized payload bytes from a received frame.
    fn extract_payload(frame: &mut StandardEitherFrame<AnyMessage<'static>>) -> Vec<u8> {
        match frame {
            StandardEitherFrame::Sv2(f) => f.payload().to_vec(),
            StandardEitherFrame::HandShake(_) => {
                panic!("post-handshake frame should always be Sv2, got HandShake")
            }
        }
    }

    /// SV2 Noise NX handshake over an in-memory duplex pair.
    ///
    /// This validates that `NoiseGenericStream<S, M>` works for any
    /// `AsyncRead + AsyncWrite + Unpin + Send` `S` (here
    /// `tokio::io::DuplexStream`), proving the abstraction can be reused for
    /// any future non-TCP transport without modifying `noise_stream.rs`.
    #[tokio::test]
    async fn noise_handshake_over_in_memory_duplex() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let (a, b) = tokio::io::duplex(64 * 1024);

        let initiator_task = tokio::spawn(async move {
            NoiseGenericStream::<_, AnyMessage<'static>>::new(
                a,
                HandshakeRole::Initiator(build_initiator()),
                Duration::from_secs(10),
            )
            .await
        });

        let responder_stream = NoiseGenericStream::<_, AnyMessage<'static>>::new(
            b,
            HandshakeRole::Responder(build_responder()),
            Duration::from_secs(10),
        )
        .await
        .expect("responder handshake");

        let initiator_stream = initiator_task
            .await
            .expect("initiator task")
            .expect("initiator handshake");

        let (_, mut initiator_writer) = initiator_stream.into_split();
        let (mut responder_reader, _) = responder_stream.into_split();

        let (frame, expected_payload) = build_setup_connection_frame();

        initiator_writer
            .write_frame(frame)
            .await
            .expect("write frame");

        let mut received = responder_reader.read_frame().await.expect("read frame");
        let decoded_payload = extract_payload(&mut received);

        assert_eq!(
            decoded_payload, expected_payload,
            "round-tripped SV2 frame payload must match"
        );
    }
}
