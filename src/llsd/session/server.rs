

use super::{SessionState, Sendable};
use chrono::{DateTime, UTC, Duration};
use llsd::errors::{LlsdResult, LlsdErrorKind};

use llsd::frames::{Frame, FrameKind};
use sodiumoxide::crypto::box_::{PublicKey, SecretKey, seal, open, gen_keypair, gen_nonce, Nonce};

#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    /// What time session should be considered exprired? Treat session as short-lived entity.
    /// There is no reason not to start a new sesion every hour.
    expire_at: DateTime<UTC>,
    created_at: DateTime<UTC>,
    /// Short-term key pair for our side
    st: (PublicKey, SecretKey),
    /// This key should be know once session transitions to Ready state.
    client_pk: PublicKey,
    client_lt_pk: Option<PublicKey>,
    state: SessionState,
}

impl Session {
    /// Create new server side session. Only requires client short-term public key. Server
    /// long-term pair stored in session manager or else where.
    pub fn new(client_pk: PublicKey) -> Session {
        Session {
            expire_at: UTC::now() + Duration::minutes(34),
            created_at: UTC::now(),
            state: SessionState::Fresh,
            st: gen_keypair(),
            client_pk: client_pk,
            client_lt_pk: None,
        }
    }
    /// Verify that session is not expired
    pub fn is_valid(&self) -> bool {
        self.expire_at > UTC::now()
    }

    /// Helper to make a Welcome frame, a reply to Hello frame. Server worflow.
    pub fn make_welcome(&mut self, hello: &Frame, our_sk: &SecretKey) -> LlsdResult<Frame> {
        if self.state != SessionState::Fresh || hello.kind != FrameKind::Hello {
            fail!(LlsdErrorKind::InvalidState)
        }
        // Verify content of the box
        if let Ok(payload) = open(&hello.payload, &hello.nonce, &hello.id, our_sk) {
            // We're not going to verify that box content itself, but will verify it's length since
            // that is what matters the most.
            if payload.len() != 256 {
                self.state = SessionState::Error;
                fail!(LlsdErrorKind::HandshakeFailed);
            }
            let nonce = gen_nonce();
            let welcome_box = seal(self.st.0.as_ref(), &nonce, &hello.id, our_sk);

            let welcome_frame = Frame {
                // Server uses client id in reply.
                id: hello.id,
                nonce: nonce,
                kind: FrameKind::Welcome,
                payload: welcome_box,
            };
            Ok(welcome_frame)
        } else {
            self.state = SessionState::Error;
            fail!(LlsdErrorKind::HandshakeFailed);
        }
    }
    /// A helper to extract client's permamanet public key from initiate frame in order to
    /// authenticate client. Authentication happens in another place.
    pub fn validate_initiate(&self, initiate: &Frame) -> Option<PublicKey> {
        if let Ok(initiate_payload) =
            open(&initiate.payload,
                 &initiate.nonce,
                 &self.client_pk,
                 &self.st.1) {
            // TODO: change to != with proper size
            if initiate_payload.len() < 60 {
                return None;
            }
            // unwrapping here because they only panic when input is shorter than needed.
            // TODO: slice that bitch properly
            let pk = PublicKey::from_slice(&initiate_payload[0..32])
                .expect("Failed to slice pk from payload");
            let v_nonce = Nonce::from_slice(&initiate_payload[32..56])
                .expect("Failed to slice nonce from payload");
            let v_box = &initiate_payload[56..initiate_payload.len()];

            if let Ok(vouch_payload) = open(v_box, &v_nonce, &pk, &self.st.1) {
                let v_pk = PublicKey::from_slice(&vouch_payload).expect("Wrong Size Key!!!");
                if vouch_payload.len() == 32 || v_pk == self.client_pk {
                    return Some(pk);
                }
            }
        }
        None
    }

    /// Helper to make a Ready frame, a reply to Initiate frame. Server workflow.
    pub fn make_ready(&mut self, initiate: &Frame, client_lt_pk: &PublicKey) -> LlsdResult<Frame> {
        if self.state != SessionState::Fresh || initiate.kind != FrameKind::Initiate {
            fail!(LlsdErrorKind::InvalidState)
        }

        // If client spend more than 3 minutes to come up with initiate - fuck him.
        if (self.created_at - UTC::now()) > Duration::minutes(3) {
            fail!(LlsdErrorKind::HandshakeFailed)
        }
        self.state = SessionState::Ready;
        self.client_lt_pk = Some(*client_lt_pk);
        let (nonce, payload) = self.seal_msg(b"My body is ready");
        let frame = Frame {
            id: initiate.id,
            nonce: nonce,
            kind: FrameKind::Ready,
            payload: payload,
        };
        Ok(frame)
    }
}
impl Sendable for Session {
    fn id(&self) -> PublicKey {
        self.client_pk
    }

    fn can_send(&self) -> bool {
        self.state == SessionState::Ready
    }

    fn seal_msg(&self, data: &[u8]) -> (Nonce, Vec<u8>) {
        let nonce = gen_nonce();
        let payload = seal(data, &nonce, &self.client_pk, &self.st.1);
        (nonce, payload)
    }

    fn read_msg(&self, frame: &Frame) -> Option<Vec<u8>> {
        if let Ok(msg) = open(&frame.payload, &frame.nonce, &self.client_pk, &self.st.1) {
            Some(msg)
        } else {
            None
        }
    }
}

impl ::std::default::Default for Session {
    fn default() -> Session {
        let (key, _) = gen_keypair();
        Session::new(key)
    }
}
