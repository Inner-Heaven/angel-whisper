use chrono::{DateTime, UTC, Duration};
use sodiumoxide::crypto::box_;

use llsd::frames::{Frame, FrameKind};
use llsd::errors::{LlsdResult, LlsdErrorKind};
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


    /// Helper to make Hello frame
    pub fn make_hello(&self) -> Frame {
        let nonce = box_::gen_nonce();
        let payload = box_::seal(&NULL_BYTES, &nonce, &self.peer_lt_pk, &self.st.1);
        Frame {
            id: self.st.0.clone(),
            nonce: nonce,
            kind: FrameKind::Hello,
            payload: payload
        }
    }
    /// Helper to make ello frame (reply to Hello)
    pub fn make_ello(&self, hello: Frame) -> LlsdResult<Frame> {
        if self.state != SessionState::Fresh {
            fail!(LlsdErrorKind::InvalidState)
        }
        unimplemented!()
    }

}

#[cfg(test)]
mod test {
}
