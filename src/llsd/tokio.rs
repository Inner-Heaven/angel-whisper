use byteorder::{BigEndian, ByteOrder};
use bytes::{BytesMut, BufMut};
use frames::Frame;
use llsd::session::client::Session as ClientSession;
use llsd::errors::LlsdErrorKind;
use std::io;
use std::result::Result;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::{Encoder, Decoder, Framed};
use tokio_proto::pipeline::{ServerProto, ClientProto};
use tokio_service::Service;


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
        let payload_len = BigEndian::read_u32(&buf[0..4]) as usize;
        if buf.len() < 4 + payload_len {
            return Ok(None);
        }
        // We have a whole frame. Consume those bytes form the buffer.
        let data = buf.split_to(4 + payload_len);
        match Frame::from_slice(&data[4..]) {
            Ok(frame) => Ok(Some(frame)),
            Err(e) => {
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
        if buf.remaining_mut() < 4 {
            buf.reserve(4);
        }
        buf.put_u32::<BigEndian>(msg.length() as u32);
        msg.pack_to_buf(buf);
        Ok(())
    }
}

pub struct WhisperPipelinedProtocol;
impl<T: AsyncRead + AsyncWrite + 'static> ServerProto<T> for WhisperPipelinedProtocol {
    type Request = Frame;
    type Response = Frame;
    type Transport = Framed<T, FrameCodec>;
    type BindTransport = Result<Self::Transport, io::Error>;
    fn bind_transport(&self, io: T) -> Self::BindTransport {
        Ok(io.framed(FrameCodec))
    }
}
impl<T: AsyncRead + AsyncWrite + 'static> ClientProto<T> for WhisperPipelinedProtocol {
    type Request = Frame;
    type Response = Frame;
    type Transport = Framed<T, FrameCodec>;
    type BindTransport = Result<Self::Transport, io::Error>;
    fn bind_transport(&self, io: T) -> Self::BindTransport {
        Ok(io.framed(FrameCodec))
    }
}

pub trait ClientHandshakeHelper {
    fn authenticate(&self, session: &mut ClientSession) -> Result<(), io::Error>;
}

impl<T> ClientHandshakeHelper for T where T: Service {
    fn authenticate(&self, session: &mut ClientSession) -> Result<(), io::Error> {
        unimplemented!()
    }

}

#[cfg(test)]
mod test {
    use super::*;
    use frames::FrameKind;
    use sodiumoxide::crypto::box_::{gen_keypair, gen_nonce};

    fn make_frame() -> Frame {
        let (pk, _) = gen_keypair();
        let payload = vec![0, 0, 0];
        let nonce = gen_nonce();

        Frame {
            id: pk,
            nonce: nonce,
            kind: FrameKind::Hello,
            payload: payload,
        }
    }

    #[test]
    fn test_decode() {
        let mut buf = BytesMut::with_capacity(70);
        let frame = make_frame();
        let mut codec = FrameCodec {};
        // First let's test if it can handle missing len
        let result = codec.decode(&mut buf);
        assert_eq!(0, buf.len());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        buf.put_u32::<BigEndian>(frame.length() as u32);

        // Message has just header
        let result = codec.decode(&mut buf);
        assert_eq!(4, buf.len());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        frame.pack_to_buf(&mut buf);

        // Message is partial
        let mut buf_partial = BytesMut::from(&buf[0..30]);
        let result = codec.decode(&mut buf_partial);
        assert_eq!(30, buf_partial.len());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Message is fully available
        let result = codec.decode(&mut buf);
        assert_eq!(0, buf.len());
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());


        buf.put_u32::<BigEndian>(frame.length() as u32);
        frame.pack_to_buf(&mut buf);
        buf.put_u32::<BigEndian>(frame.length() as u32);

        // Two messages at once
        let result = codec.decode(&mut buf);
        assert_eq!(4, buf.len());
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_encode() {
        let frame = make_frame();
        let mut buf = BytesMut::new();
        let mut codec = FrameCodec {};

        let result = codec.encode(frame.clone(), &mut buf);
        assert!(result.is_ok());
        let payload_len = BigEndian::read_u32(&buf[0..4]) as usize;
        assert_eq!(frame.length(), payload_len);
    }
}
