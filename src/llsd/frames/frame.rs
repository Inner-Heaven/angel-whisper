use bytes::{BufMut, Bytes, BytesMut};

use llsd::errors::{LlsdError, LlsdResult};
use nom::{IResult, rest};
use sodiumoxide::crypto::box_::{Nonce, PublicKey};

/// Header size in bytes. Used to pre-allocate vector of correct size.
pub const HEADER_SIZE: usize = 57;


/// Frame type.
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum FrameKind {
    /// Initial frame. Sent from client.
    Hello = 1,
    /// Reply to initial frame. Sent from server.
    Welcome,
    /// Authentication frame. Sent from client.
    Initiate,
    /// After successful handshake this frame is sent from server.
    Ready,
    /// Generic message frame. Can be sent from either side.
    Message,
    /// Termination frame. Usually used to indicate handshake error or session
    /// termination. Can be
    /// sent from either side.
    Termination,
}

/// Each frame has it's kind. Meant to be expandable.
impl FrameKind {
    /// Since we don't have TryFrom...
    pub fn from(kind: u8) -> Option<FrameKind> {
        match kind {
            1 => Some(FrameKind::Hello),
            2 => Some(FrameKind::Welcome),
            3 => Some(FrameKind::Initiate),
            4 => Some(FrameKind::Ready),
            5 => Some(FrameKind::Message),
            6 => Some(FrameKind::Termination),
            _ => None,
        }
    }
    /// Alias to method above, but returns an error if there're more than one
    /// byte,
    pub fn from_slice(kind: &[u8]) -> Option<FrameKind> {
        if kind.len() != 1 {
            return None;
        }
        FrameKind::from(kind[0])
    }
}

/// Main unit of information passed from client to server. This thing doesn't
/// care what payload it as long as Frame has correct header.
/// This way you can used whatever you want as your internal message format —
/// JSON, BSON, TSV, Protocol Buffers, etc.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    /// Session identificator. 32 bytes
    pub id: PublicKey,
    /// Nonce used to encrypt payload. 24 bytes
    pub nonce: Nonce,
    /// Message type as u8 BigEndian. 1 byte
    pub kind: FrameKind,
    /// Payload (that may or may not be encrypted)
    pub payload: Vec<u8>,
}

/// Main unit of information passed from client to server. This thing doesn't
/// care what payload it as long as Frame has correct header.
/// This way you can used whatever you want as your internal message format —
/// JSON, BSON, TSV, Protocol Buffers, etc.
impl Frame {
    /// Calculates length of a frame;
    pub fn length(&self) -> usize {
        HEADER_SIZE + self.payload.len()
    }

    /// Writes packed bytes to supplied buffer. This doesn't include legnth of
    /// the message.
    pub fn pack_to_buf(&self, buf: &mut BytesMut) {
        buf.reserve(self.length());
        // Unwrap here makes sense, amirite?
        // kind.write_u8(self.kind as u8).unwrap();
        buf.extend_from_slice(&self.id.0);
        buf.extend_from_slice(&self.nonce.0);
        buf.put_u8(self.kind as u8);
        buf.extend_from_slice(&self.payload);
        ()
    }
    /// Pack frame header and its payload into Vec<u8>.
    pub fn pack(&self) -> Bytes {
        let mut frame = BytesMut::with_capacity(self.length());
        self.pack_to_buf(&mut frame);
        frame.freeze()
    }

    /// Parse packed frame.
    pub fn from_slice(i: &[u8]) -> LlsdResult<Frame> {
        match parse_frame(i) {
            IResult::Done(_, frame) => Ok(frame),
            IResult::Incomplete(_) => Err(LlsdError::IncompleteFrame),
            IResult::Error(_) => Err(LlsdError::BadFrame),
        }
    }
}


named!(parse_frame < &[u8], Frame >,
       do_parse!(
           pk:          map_opt!(take!(32), PublicKey::from_slice)  >>
           nonce:       map_opt!(take!(24), Nonce::from_slice)      >>
           kind:        map_opt!(take!(1),  FrameKind::from_slice)  >>
           payload:     rest                                        >>
           ({
               let mut vec = Vec::with_capacity(payload.len());
               vec.extend(payload.iter().cloned());
               Frame {
                   id: pk,
                   nonce: nonce,
                   kind: kind,
                   payload: vec
               }
           })
           )
      );


#[cfg(test)]
mod test {
    use super::*;

    use llsd::errors::LlsdError;
    use sodiumoxide::crypto::box_::{gen_keypair, gen_nonce};

    #[test]
    fn pack_and_unpack() {
        let frame = make_frame();
        let packed_frame = frame.pack();
        assert_eq!(packed_frame.len(), 60);

        let parsed_frame = Frame::from_slice(&packed_frame);

        assert_eq!(frame, parsed_frame.unwrap());
    }

    #[test]
    fn malformed_frame() {
        let packed_frame = vec![1 as u8, 2, 3];

        let parsed_frame = Frame::from_slice(&packed_frame);

        assert_eq!(parsed_frame.is_err(), true);
        let err = parsed_frame.err().unwrap();
        match err {
            LlsdError::IncompleteFrame => assert!(true),
            _ => panic!("WRONG ERROR KIND"),
        }
}

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
}
