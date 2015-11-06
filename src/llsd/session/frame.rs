use sodiumoxide::crypto::box_::{Nonce, PublicKey};

use nom::{IResult, Needed, be_i64, rest};
use nom::IResult::{Done, Error, Incomplete};

use errors::{AWResult, AWError};

#[derive(Debug, PartialEq)]
pub struct Frame {
    pub header:     FrameHeader,
    pub payload:    FramePayload
}

impl Frame {
    pub fn from_slice(input: &[u8]) -> Option<Frame> {
        match parse_frame(input) {
            Done(_, frame) => Some(frame),
            _              => None
        }
    }

    pub fn new(header: FrameHeader, payload: FramePayload) -> Frame {
        Frame {
            header: header,
            payload: payload
        }
    }
}


#[derive(PartialEq, Debug)]
pub enum FramePayload {
    Hello(Vec<u8>)
}
impl FramePayload {
    pub fn id(&self) -> &[u8] {
        match *self {
            FramePayload::Hello(_) => b"c37707"
        }
    }

    pub fn from_slice(input: &[u8]) -> Option<FramePayload> {
        match &input[0 .. 6] {
            b"c37707"   => Some(FramePayload::Hello(input[6..].to_vec())),
            _           => None
        }
    }

    pub fn pack(&self) -> Vec<u8> {
        match *self {
            FramePayload::Hello(ref nulls)  => { nulls.clone() }
        }
    }

}


fn unpack_frame(input: &[u8]) -> IResult<&[u8],()> {
    match be_i64(input) {
        Done(i, len) => {
            if input.len() >= len as usize {
                Done(&i, ())
            } else {
                Incomplete(Needed::Size(len as usize))
            }
        }
        Error(e)        => Error(e),
        Incomplete(e)   => Incomplete(e)
    }
}

/// Helper struct for creating new frames that can be sent on the wire
/// 32 bytes — Client short-term public key
/// 24 bytes — Nonce. Can't be used twice!
/// N  bytes — Secured Payload
#[derive(PartialEq, Debug)]
pub struct FrameHeader {
    /// 32 bytes session identificator
    pub pk:         PublicKey,
    /// 24 bytes nonce to decrypt the payload
    pub nonce:      Nonce,
}

named!(parse_frame_header < &[u8], FrameHeader >,
       chain!(
           pk:         map_opt!(take!(32), PublicKey::from_slice)  ~
           nonce:      map_opt!(take!(24), Nonce::from_slice),
           || {
               FrameHeader {
                   pk: pk,
                   nonce: nonce
               }
           }
           )
      );

pub fn pack(frame: &Frame) -> Vec<u8> {
    let payload = frame.payload.pack();
    let header = &frame.header;
    let frame_size: usize = 70 + (payload.len());

    let mut msg = Vec::with_capacity(frame_size);

    msg.extend(header.pk.0.iter().cloned());
    msg.extend(header.nonce.0.iter().cloned());
    msg.extend(frame.payload.id().iter().cloned());
    msg.extend(payload.clone());
    msg
}


named!(parse_frame < &[u8], Frame >,
       chain!(
           header:     parse_frame_header                      ~
           payload:    map_opt!(rest, FramePayload::from_slice),
           || {
               Frame::new(header, payload)
           }
           )
      );
