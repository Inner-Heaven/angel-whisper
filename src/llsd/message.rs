use uuid::Uuid;
use sodiumoxide::crypto::box_::Nonce;
use bincode::rustc_serialize::{encode, decode};
use bincode::SizeLimit;
use sodiumoxide::crypto::box_::{gen_nonce};

use super::session::Session;

pub enum Command {
    Hello
}

impl Command {
    pub fn id(&self) -> &str {
        match *self {
            Command::Hello => "c37707"
        }
    }
    pub fn from_id(id: &str) -> Option<Command> {
        match id {
            "c37707"    => Some(Command::Hello),
            _           => None
        }
    }
}

pub struct Message {
    id:         Uuid,
    nonce:      Nonce,
    kind:       Command,
    payload:    Vec<u8>
}

impl Message {
    pub fn pack(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(128);
        msg.extend(self.id.as_bytes().iter().cloned());
        println!("Vec size with id: {}", msg.len());
        msg.extend(self.kind.id().as_bytes().iter().cloned());
        println!("Vec size with command: {}", msg.len());
        msg.extend(self.nonce.0.iter().cloned());
        println!("Vec size with nonce: {}", msg.len());
        msg.extend(encode(&self.payload.len(), SizeLimit::Infinite).unwrap());
        println!("Vec size with size: {}", msg.len());
        msg.extend(self.payload.clone());
        println!("Vec size with payload: {}", msg.len());
        msg
    }

    pub fn hello(session: Session) -> Message {
        let nonce = gen_nonce();
        Message {
            id: session.id(),
            kind: Command::Hello,
            nonce: nonce,
            payload: session.hello_payload(&nonce)
        }
    }
}
