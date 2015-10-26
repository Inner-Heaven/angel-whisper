use uuid::Uuid;
use chrono::{DateTime, UTC, Duration};
use sodiumoxide::crypto::box_;

use bincode::rustc_serialize::{encode, decode};
use bincode::SizeLimit;

#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    Fresh,
    Ready,
    Error
}

#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    id: Uuid,
    expire_at: DateTime<UTC>,

    /// Short-term key pair for our side
    st: (box_::PublicKey, box_::SecretKey),
    peer_pk: Option<box_::PublicKey>,
    peer_lt_pk: box_::PublicKey,
    state: SessionState
}

impl Session {
    #[doc(hidden)]
    pub fn empty() -> Session {
        let (key, _) = box_::gen_keypair();
         Session {
            id: Uuid::nil(),
            expire_at: UTC::now() + Duration::minutes(34),
            state: SessionState::Fresh,
            st: box_::gen_keypair(),
            peer_pk: None, // Short-term key
            peer_lt_pk: key // Long-term key
        }
    }

    pub fn new(peer_lt_key: box_::PublicKey) -> Session {
        Session {
            id: Uuid::new_v4(),
            expire_at: UTC::now() + Duration::minutes(34),
            state: SessionState::Fresh,
            st: box_::gen_keypair(),
            peer_pk: None,
            peer_lt_pk: peer_lt_key
        }
    }

    pub fn is_null(&self) -> bool {
        self.id == Uuid::nil()
    }

    pub fn is_valid(&self) -> bool {
        !self.is_null() && self.expire_at > UTC::now()
    }

    pub fn can_send(&self) -> bool {
        self.state == SessionState::Ready
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn hello_payload(&self, nonce: &box_::Nonce) -> Vec<u8> {
        box_::seal(self.st.0.as_ref(), nonce, &self.peer_lt_pk, &self.st.1)
    }

    /// Generate HELLO message.
    //pub fn make_hello<'a>(&self) -> Message {
    /*    let nonce   = box_::gen_nonce();
        let payload = box_::seal(self.st.0.as_ref(), &nonce, &self.peer_lt_pk, &self.st.1);

        Message {
            id:         self.id().clone(),
            nonce:      nonce,
            kind:       Command::Hello,
            payload:    payload
        }
    }*/

    fn print_msg(msg: Vec<u8>) {
        let strs: Vec<String> = msg.iter()
                                    .map(|b| format!("{:02X}", b))
                                    .collect();
        println!("MSG: {}", strs.join(" "));
    }

}
/*
#[cfg(test)]
mod test {
    use sodiumoxide::crypto::box_;

    use super::*;

    fn key() -> (box_::PublicKey, box_::SecretKey) {
        box_::gen_keypair()
    }

    #[test]
    fn hello() {
        let key     = key();
        let session = Session::new(key.0);
        let msg     = session.make_hello().pack();

        assert_eq!(&msg[0 .. 16], session.id().as_bytes());
        assert_eq!(&msg[16 .. 22], Command::Hello.id().as_bytes());

        let payload = &msg[22 .. 70];
    }
}*/
