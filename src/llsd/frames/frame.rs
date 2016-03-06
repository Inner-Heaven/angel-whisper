use std::convert::From;

use sodiumoxide::crypto::box_::{Nonce, PublicKey};
use byteorder::{WriteBytesExt};
use nom::{rest, IResult};

use ::errors::{AWResult, AWErrorKind};

pub const HEADER_SIZE: usize = 57;

#[derive(Debug, Clone, PartialEq, Copy)]
pub enum FrameKind {
    Hello = 1,
    Welcome,
    Initiate,
    Ready,
    Message
}

impl FrameKind {
    pub fn from(kind: u8) -> Option<FrameKind> {
        match kind {
            1 => Some(FrameKind::Hello),
            2 => Some(FrameKind::Welcome),
            3 => Some(FrameKind::Initiate),
            4 => Some(FrameKind::Ready),
            5 => Some(FrameKind::Message),
            _ => None
        }
    }
    pub fn from_slice(kind: &[u8]) -> Option<FrameKind> {
        if kind.len() != 1 {
            return None;
        }
        FrameKind::from(kind[0])
    }
}


#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    /// Session identificator. 32 bytes
    pub id: PublicKey,
    /// Nonce used to encrypt payload. 24 bytes
    pub nonce: Nonce,
    /// Message type as u8 BigEndian. 1 byte
    pub kind: FrameKind,
    /// Payload (that may or may not be encrypted)
    pub payload: Vec<u8>
}

impl Frame {
    pub fn pack(&self) -> Vec<u8> {
        let frame_size = HEADER_SIZE + self.payload.len();
        let mut frame = Vec::with_capacity(frame_size);

        let mut kind = Vec::with_capacity(1);
        // Unwrap here makes sense, amirite?
        kind.write_u8(self.kind.clone() as u8).unwrap();
        frame.extend(self.id.0.iter().cloned());
        frame.extend(self.nonce.0.iter().cloned());
        frame.extend(kind.clone());
        frame.extend(self.payload.clone());
        frame
    }

    pub fn from_slice(i: &[u8]) -> AWResult<Frame> {
        match parse_frame(i) {
            IResult::Done(_, frame) => Ok(frame),
            _                       => fail!(AWErrorKind::BadFrame)
        }
    }
}


named!(parse_frame < &[u8], Frame >,
       chain!(
           pk:          map_opt!(take!(32), PublicKey::from_slice)  ~
           nonce:       map_opt!(take!(24), Nonce::from_slice)      ~
           kind:        map_opt!(take!(1),  FrameKind::from_slice)  ~
           payload:     rest,
           || {
               let mut vec = Vec::with_capacity(payload.len());
               vec.extend(payload.iter().cloned());
               Frame {
                   id: pk,
                   nonce: nonce,
                   kind: kind,
                   payload: vec
               }
           }
           )
      );


#[cfg(test)]
mod test {
    use sodiumoxide::crypto::box_::{gen_keypair, gen_nonce};
    use super::*;

    #[test]
    fn pack_and_unpack() {
        let frame = make_frame();
        let packed_frame = frame.pack();
        assert_eq!(packed_frame.len(), 60);

        let parsed_frame = Frame::from_slice(&packed_frame);

        assert_eq!(frame, parsed_frame.unwrap());
    }

    #[test]
    #[should_panic]
    fn malformed_frame() {
        let packed_frame = vec![1 as u8, 2,3];

        let parsed_frame = Frame::from_slice(&packed_frame);

        parsed_frame.unwrap();
    }

    fn make_frame() -> Frame {
        let (pk, _)    = gen_keypair();
        let payload     = vec![0,0,0];
        let nonce       = gen_nonce();

        Frame {
            id:     pk,
            nonce:  nonce,
            kind:   FrameKind::Hello,
            payload:payload
        }
    }
}
