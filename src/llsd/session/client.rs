

use super::{SessionState, KeyPair, NULL_BYTES, Sendable};
use chrono::{DateTime};
use chrono::offset::Utc;
use llsd::errors::{LlsdResult, LlsdErrorKind};

use llsd::frames::{Frame, FrameKind};
use sodiumoxide::crypto::box_::{PublicKey, seal, open, gen_keypair, gen_nonce, Nonce};

const READY_PAYLOAD: &'static [u8; 16] = b"My body is ready";


/// Client side session.
#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    created_at: DateTime<Utc>,
    st: KeyPair,
    our_pair: KeyPair,
    state: SessionState,
    server_pk: Option<PublicKey>,
    server_lt_pk: PublicKey,
}

impl Session {
    /// Create new client session. Requires client long-term key-pair and server long-term public
    /// key.
    pub fn new(server_lt_pk: PublicKey, our_pair: KeyPair) -> Session {
        Session {
            created_at: Utc::now(),
            st: gen_keypair(),
            our_pair: our_pair,
            state: SessionState::Fresh,
            server_pk: None,
            server_lt_pk: server_lt_pk,
        }
    }
    /// Helper to make Hello frame. Client workflow.
    pub fn make_hello(&self) -> Frame {
        let nonce = gen_nonce();
        let payload = seal(&NULL_BYTES, &nonce, &self.server_lt_pk, &self.st.1);
        Frame {
            id: self.st.0,
            nonce: nonce,
            kind: FrameKind::Hello,
            payload: payload,
        }
    }
    /// Helper to make am Initiate frame, a reply to Welcome frame. Client workflow.
    pub fn make_initiate(&mut self, welcome: &Frame) -> LlsdResult<Frame> {
        if self.state != SessionState::Fresh || welcome.kind != FrameKind::Welcome {
            fail!(LlsdErrorKind::InvalidState)
        }
        // Try to obtain server short public key from the box.
        if let Ok(server_pk) = open(&welcome.payload,
                                    &welcome.nonce,
                                    &self.server_lt_pk,
                                    &self.st.1) {
            if let Some(key) = PublicKey::from_slice(&server_pk) {
                self.server_pk = Some(key);
                let mut initiate_box = Vec::with_capacity(104);
                let our_pk = &self.our_pair.0;
                initiate_box.extend_from_slice(&our_pk.0);
                initiate_box.extend(self.vouch());
                let nonce = gen_nonce();
                let payload = seal(&initiate_box,
                                   &nonce,
                                   &self.server_pk.expect("Shit is on fire yo"),
                                   &self.st.1);
                let frame = Frame {
                    id: welcome.id,
                    nonce: nonce,
                    kind: FrameKind::Initiate,
                    payload: payload,
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

    /// Verify that reply to initiate frame is correct ready frame. Changes session state if so. 
    pub fn read_ready(&mut self, ready: &Frame) -> LlsdResult<()> {
        if self.state != SessionState::Fresh || ready.kind != FrameKind::Ready {
            fail!(LlsdErrorKind::InvalidState)
        }
        if let Some(msg) = self.read_msg(ready) {
            if msg == READY_PAYLOAD {
                self.state = SessionState::Ready;
                return Ok(());
            }
        }
        fail!(LlsdErrorKind::HandshakeFailed);
    }

    // Helper to make a vouch
    fn vouch(&self) -> Vec<u8> {
        let nonce = gen_nonce();
        let our_sk = &self.our_pair.1;
        let pk = &self.st.1;
        let vouch_box = seal(&pk.0,
                             &nonce,
                             &self.server_pk.expect("Shit is on fire yo"),
                             our_sk);

        let mut vouch = Vec::with_capacity(72);
        vouch.extend_from_slice(&nonce.0);
        vouch.extend(vouch_box);
        vouch
    }
}


impl Sendable for Session {
    fn id(&self) -> PublicKey {
        self.st.0
    }

    fn can_send(&self) -> bool {
        self.state == SessionState::Ready
    }

    fn seal_msg(&self, data: &[u8]) -> (Nonce, Vec<u8>) {
        let nonce = gen_nonce();
        let payload = seal(data, &nonce, &self.server_pk.unwrap(), &self.st.1);
        (nonce, payload)
    }

    fn read_msg(&self, frame: &Frame) -> Option<Vec<u8>> {
        if let Ok(msg) = open(&frame.payload,
                              &frame.nonce,
                              &self.server_pk.expect("Shit is on fire yo!"),
                              &self.st.1) {
            Some(msg)
        } else {
            None
        }
    }
}
