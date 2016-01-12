use nom::rest;
use sodiumoxide::crypto::box_::{Nonce, PublicKey};


use super::Request;

named!(pub parse_request < &[u8], Request >,
       chain!(
           pk:         map_opt!(take!(32), PublicKey::from_slice)  ~
           nonce:      map_opt!(take!(24), Nonce::from_slice)      ~
           payload:    rest,
           || {
               let mut vec = Vec::with_capacity(payload.len());
               vec.extend(payload.iter().cloned());
               Request {
                   id: pk,
                   nonce: nonce,
                   payload: vec
               }
           }
           )
      );
