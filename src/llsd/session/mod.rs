use chrono::{DateTime, UTC, Duration};
use sodiumoxide::crypto::box_;

use llsd::request::{Request, Payload};

/// Array of null bytes used in Hello package. It's big to prevent amplifiction attacks.
pub static NULL_BYTES: [u8; 256] = [b'\x00'; 256];


#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    /// This state means that client have sent Hello frame.
    Fresh,
    /// This state means that session is established and messages can be sent both ways.
    Ready,
    /// This state means that session established, but can't be used at the time
    Error
}

#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    /// What time session should be considered exprired? Treat session as short-lived entity.
    /// There is no reason not to start a new sesion every hour.
    expire_at: DateTime<UTC>,

    /// Short-term key pair for our side
    st: (box_::PublicKey, box_::SecretKey),
    /// This key should be know once session transitions to Ready state.
    peer_pk: Option<box_::PublicKey>,
    peer_lt_pk: box_::PublicKey,
    state: SessionState
}

impl Session {
    /// The only proper construction function you should use. Please note that local _long-term_ keys are not part of the sesion.
    pub fn new(peer_lt_pk: box_::PublicKey) -> Session {
        Session {
            expire_at: UTC::now() + Duration::minutes(34),
            state: SessionState::Fresh,
            st: box_::gen_keypair(),
            peer_pk: None,
            peer_lt_pk: peer_lt_pk
        }
    }

    /// Shortcut to verify that session is not expired
    pub fn is_valid(&self) -> bool {
        self.expire_at > UTC::now()
    }

    /// Shortcut to verify that session is in Ready state
    pub fn can_send(&self) -> bool {
        self.state == SessionState::Ready
    }

    /// Getter for short-term public key
    pub fn id(&self) -> &box_::PublicKey {
        &self.st.0
    }


    /// Helper function used to generate Requests. Maybe this should exist outside of Session...
    pub fn make_request(&self, payload: Payload) -> Request {
        match payload {
            Payload::Hello(_) => self.hello(),
            _ => unimplemented!()
        }
    }

    /// Helper to make Hello frame
    fn hello(&self) -> Request {
        let nonce = box_::gen_nonce();
        let payload = box_::seal(&NULL_BYTES, &nonce, &self.peer_lt_pk, &self.st.1);
        Request {
            id: self.st.0.clone(),
            nonce: nonce,
            payload: payload
        }
    }

}

#[cfg(test)]
mod test {
    use sodiumoxide::crypto::box_::{gen_keypair, open};

    use llsd::request::{Request, Payload};
    use super::{Session};
    #[test]
    fn create_and_pack_hello() {
        let key = gen_keypair();
        let session = Session::new(key.0);

        let msg: Request = session.make_request(Payload::Hello(Vec::new()));
        let bytes = msg.pack();

        let parsed = Request::from_slice(&bytes).unwrap();
        assert_eq!(parsed, msg);

        let payload = open(&parsed.payload, &parsed.nonce, &parsed.id, &key.1).unwrap();
        assert_eq!(payload, vec![b'\x00'; 256]);
    }
}
