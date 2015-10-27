use chrono::{DateTime, UTC, Duration};
use sodiumoxide::crypto::box_;


pub static NULL_BYTES: [u8; 64] = [b'\x00'; 64];

#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    Fresh,
    Ready,
    Error
}

#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    expire_at: DateTime<UTC>,

    /// Short-term key pair for our side
    st: (box_::PublicKey, box_::SecretKey),
    peer_pk: Option<box_::PublicKey>,
    peer_lt_pk: box_::PublicKey,
    state: SessionState
}

impl Session {
    pub fn new(peer_lt_pk: box_::PublicKey) -> Session {
        Session {
            expire_at: UTC::now() + Duration::minutes(34),
            state: SessionState::Fresh,
            st: box_::gen_keypair(),
            peer_pk: None,
            peer_lt_pk: peer_lt_pk
        }
    }

    pub fn is_valid(&self) -> bool {
        self.expire_at > UTC::now()
    }

    pub fn can_send(&self) -> bool {
        self.state == SessionState::Ready
    }

    pub fn id(&self) -> &box_::PublicKey {
        &self.st.0
    }

    pub fn hello_payload(&self, nonce: &box_::Nonce) -> Vec<u8> {
        box_::seal(&NULL_BYTES, nonce, &self.peer_lt_pk, &self.st.1)
    }
}
