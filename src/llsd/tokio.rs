
#[cfg(feature = "system-on-tokio")]
pub mod tokio {
    use llsd::errors::{LlsdErrorKind};
    use frames::Frame;
    use tokio_io::{AsyncRead, AsyncWrite};
    use tokio_io::codec::{Encoder, Decoder, Framed};
    use tokio_proto::pipeline::ServerProto;
    use bytes::BytesMut;
    use std::io;
    use std::result::Result;
    use byteorder::{BigEndian, ByteOrder};

    pub struct FrameCodec;

    impl Decoder for FrameCodec {
        type Item = Frame;
        type Error = io::Error;
        fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Frame>> {
            // Check that if we have at least 4 bytes to read
            if buf.len() < 4 {
                return Ok(None);
            }
            // Check that if we have the whole payload
            let payload_len = BigEndian::read_u32(&buf[0..3]) as usize;
            if buf.len() < 4 + payload_len {
                return Ok(None);
            }
            // We have a whole frame. Consume those bytes form the buffer.
            let data = buf.split_to(4 + payload_len);
            match Frame::from_slice(&data[4..]) {
                Ok(frame)   => Ok(Some(frame)),
                Err(e)      => {
                    if *e == LlsdErrorKind::IncompleteFrame {
                        Ok(None)
                    } else {
                        Err(e.into())
                    }
                }
            }
        }
    }

    impl Encoder for FrameCodec {
        type Item = Frame;
        type Error = io::Error;
            fn encode(&mut self, msg: Frame, buf: &mut BytesMut) -> io::Result<()> {
                BigEndian::write_u32(buf, msg.length() as u32);
                msg.pack_to_buf(buf);
                Ok(())
            }
    }

    pub struct WhisperPipelinedProtocol;
    impl<T: AsyncRead + AsyncWrite + 'static> ServerProto<T> for WhisperPipelinedProtocol {
        type Request        = Frame;
        type Response       = Frame;
        type Transport      = Framed<T, FrameCodec>;
        type BindTransport  = Result<Self::Transport, io::Error>;
        fn bind_transport(&self, io: T) -> Self::BindTransport {
            Ok(io.framed(FrameCodec))
        }
    }
}
