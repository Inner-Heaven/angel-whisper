use sodiumoxide::crypto::box_::{seal, Nonce, PublicKey};
use sodiumoxide::crypto::box_::gen_nonce;
use nom::{IResult};

use llsd::session::Session;
use super::parser::parse_request;

#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    /// Session identificator. 32 bytes
    pub id: PublicKey,
    /// Nonce used to encrypt payload. 24 bytes
    pub nonce: Nonce,
    /// Payload
    pub payload: Vec<u8>
}

impl Request {
    pub fn pack(&self) -> Vec<u8> {
        let frame_size =  56 + self.payload.len();
        let mut frame = Vec::with_capacity(frame_size);

        frame.extend(self.id.0.iter().cloned());
        frame.extend(self.nonce.0.iter().cloned());
        frame.extend(self.payload.clone());
        frame
    }

    pub fn from_slice(i: &[u8]) -> Option<Request> {
        match parse_request(i) {
            IResult::Done(_, request)    => Some(request),
            _                   => None
        }
    }
}
