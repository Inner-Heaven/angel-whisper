use chrono::{DateTime, UTC, Duration};
use sodiumoxide::crypto::box_;

use llsd::frames::{Frame, FrameKind};
use llsd::errors::{LlsdResult, LlsdErrorKind};
/// Array of null bytes used in Hello package. It's big to prevent amplifiction attacks.
pub static NULL_BYTES: [u8; 256] = [b'\x00'; 256];

/// Session has three states. Each state means different thing on client and server. For example,
/// on client Fresh state means that client has send Hello frame to server. On the server, this
/// means server recieved Hello and replied with Welcome. In case Hello was rejected - server goes
/// into Error state and session is ready to be securely erased by reaper.
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
    created_at: DateTime<UTC>,

    /// Short-term key pair for our side
    st: (box_::PublicKey, box_::SecretKey),
    /// This key should be know once session transitions to Ready state.
    peer_pk: Option<box_::PublicKey>,
    peer_lt_pk: Option<box_::PublicKey>,
    state: SessionState
}

impl Session {
    /// The only proper construction function you should use. Please note that local _long-term_ keys are not part of the sesion.
    pub fn client_session(peer_lt_pk: box_::PublicKey) -> Session {
        Session {
            expire_at: UTC::now() + Duration::minutes(34),
            created_at: UTC::now(),
            state: SessionState::Fresh,
            st: box_::gen_keypair(),
            peer_pk: None,
            peer_lt_pk: Some(peer_lt_pk)
        }
    }
    pub fn server_session(peer_pk: box_::PublicKey) -> Session {
        Session {
            expire_at: UTC::now() + Duration::minutes(34),
            created_at: UTC::now(),
            state: SessionState::Fresh,
            st: box_::gen_keypair(),
            peer_pk: Some(peer_pk),
            peer_lt_pk: None
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
    pub fn id(&self) -> Option<&box_::PublicKey> {
        &self.peer_pk
    }


    /// Helper to make Hello frame. Client workflow.
    pub fn make_hello(&self) -> Frame {
        let nonce = box_::gen_nonce();
        let payload = box_::seal(&NULL_BYTES, &nonce, &self.peer_lt_pk.unwrap(), &self.st.1);
        Frame {
            id: self.st.0.clone(),
            nonce: nonce,
            kind: FrameKind::Hello,
            payload: payload
        }
    }
    /// Helper to make a Welcome frame, a reply to Hello frame. Server worflow.
    pub fn make_welcome(&mut self, hello: &Frame, our_sk: &box_::SecretKey) -> LlsdResult<Frame> {
        if self.state != SessionState::Fresh || hello.kind != FrameKind::Hello {
            fail!(LlsdErrorKind::InvalidState)
        }
        // Verify content of the box
        if let Ok(payload) = box_::open(&hello.payload, &hello.nonce, &hello.id, &our_sk) {
            // We're not going to verify that box content itself, but will verify it's length since
            // that is what matters the most.
            if payload.len() != 256 {
                self.state = SessionState::Error;
                fail!(LlsdErrorKind::HandshakeFailed);
            }
            self.peer_pk = Some(hello.id.clone());
            let nonce = box_::gen_nonce();
            let welcome_box = box_::seal(self.st.0.as_ref(), &nonce, &hello.id, &our_sk);

            let welcome_frame = Frame {
                // Server uses client id in reply for lulz.
                id: hello.id.clone(),
                nonce: nonce,
                kind: FrameKind::Welcome,
                payload: welcome_box
            };
            Ok(welcome_frame)
        } else {
            self.state = SessionState::Error;
            fail!(LlsdErrorKind::HandshakeFailed);
        }
    }

    /// Helper to make am Initiate frame, a reply to Welcome frame. Client workflow.
    pub fn make_initiate(&mut self, welcome: &Frame, our_sk: &box_::SecretKey, our_pk: &box_::PublicKey) -> LlsdResult<Frame> {
        if self.state != SessionState::Fresh || welcome.kind != FrameKind::Welcome {
            fail!(LlsdErrorKind::InvalidState)
        }
        // Try to obtain server short public key from the box.
        if let Ok(server_pk) = box_::open(&welcome.payload, &welcome.nonce, &self.peer_lt_pk.unwrap(), &self.st.1) {
            if let Some(key) = box_::PublicKey::from_slice(&server_pk) {
                self.peer_pk = Some(key);
                let mut initiate_box = Vec::with_capacity(32);
                initiate_box.extend_from_slice(&our_pk.0);
                initiate_box.extend(self.vouch(our_sk));

                let nonce = box_::gen_nonce();
                let payload = box_::seal(&initiate_box, &nonce, &self.peer_pk.expect("Shit is on fire yo"), &self.st.1);
                let frame = Frame {
                    id: welcome.id.clone(),
                    nonce: nonce,
                    kind: FrameKind::Initiate,
                    payload: payload
                };
                Ok(frame)
            } else {
                self.state = SessionState::Error;
                fail!(LlsdErrorKind::HandshakeFailed);
            }
        } else {
            self.state = SessionState::Error;
            fail!(LlsdErrorKind::HandshakeFailed);
        }
    }


    /// A helper to extract client's permamanet public key from initiate frame in order to
    /// authenticate client. Authentication happens in another place.
    pub fn validate_initiate(&self, initiate: &Frame) -> Option<box_::PublicKey> {
        if let Ok(initiate_payload) = box_::open(&initiate.payload, &initiate.nonce, &self.peer_pk.expect("Shit is on fire yo"), &self.st.1) {
            // TODO: change to != with proper size
            if initiate_payload.len() < 60 {
                return None;
            }
            // unwrapping here because they only panic when input is shorter than needed.
            // TODO: slice that bitch properly
            let pk      = box_::PublicKey::from_slice(&initiate_payload[0..31]).expect("Shit is on fire yo");
            let v_nonce = box_::Nonce::from_slice(&initiate_payload[32..56]).expect("Shit is on fire yo");
            let v_box   = &initiate_payload[57..initiate_payload.len() - 1];

            if let Ok(vouch_payload) = box_::open(&v_box, &v_nonce, &pk, &self.st.1) {
                let v_pk = box_::PublicKey::from_slice(&vouch_payload);
                if vouch_payload.len() == 32 || v_pk == self.peer_pk {
                    return Some(pk);
                }
            }
        }
        return None;
    }

    /// Helper to make a Ready frame, a reply to Initiate frame. Server workflow.
    pub fn make_ready(&mut self, initiate: &Frame) -> LlsdResult<Frame> {
        if self.state != SessionState::Fresh || initiate.kind != FrameKind::Initiate {
            fail!(LlsdErrorKind::InvalidState)
        }

        // If client spend more than 3 minutes to come up with intiate, fuck that slowpoke.
        if (self.created_at - UTC::now()) > Duration::minutes(3) {
            fail!(LlsdErrorKind::HandshakeFailed)
        }
        self.state = SessionState::Ready;
        let (nonce, payload) = self.seal_msg(b"My body is ready");
        let frame = Frame {
            id: initiate.id.clone(),
            nonce: nonce,
            kind: FrameKind::Ready,
            payload: payload
        };
        Ok(frame)
    }

    pub fn make_message(&self, data: &[u8]) -> LlsdResult<Frame> {
        if self.state != SessionState::Ready {
            fail!(LlsdErrorKind::InvalidState)
        }
        let (nonce, payload) = self.seal_msg(data);
        let frame = Frame {
            id: self.peer_pk.unwrap().clone(),
            nonce: nonce,
            kind: FrameKind::Message,
            payload: payload
        };
        Ok(frame)
    }


    fn seal_msg(&self, data: &[u8]) -> (box_::Nonce, Vec<u8>) {
        let nonce = box_::gen_nonce();
        let payload = box_::seal(&data, &nonce, &self.peer_pk.unwrap(), &self.st.1);
        (nonce, payload)
    }

    fn vouch(&self, our_sk: &box_::SecretKey) -> Vec<u8> {
        let nonce = box_::gen_nonce();
        let pk = &self.st.1;
        let vouch_box = box_::seal(&pk.0, &nonce, &self.peer_pk.unwrap() ,&our_sk);
        println!("Vouch box size: {}", vouch_box.len());
        let mut vouch = Vec::with_capacity(90);
        vouch.extend_from_slice(&nonce.0);
        vouch.extend(vouch_box);
        vouch
    }
}

#[cfg(test)]
mod test {
}
