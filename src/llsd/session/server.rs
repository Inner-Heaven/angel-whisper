

use super::{Sendable, SessionState};
use chrono::{DateTime, Duration};
use chrono::offset::Utc;
use llsd::errors::{LlsdError, LlsdResult};
use bytes::{Bytes, BytesMut};
use llsd::frames::{Frame, FrameKind};
use sodiumoxide::crypto::box_::{Nonce, PublicKey, SecretKey, gen_keypair, gen_nonce, open, seal};

const READY_PAYLOAD: &'static [u8; 16] = b"My body is ready";


#[derive(Debug, Clone, PartialEq)]
/// Server side session.
pub struct Session {
    /// What time session should be considered exprired? Treat session as
    /// short-lived entity.
    /// There is no reason not to start a new sesion every hour.
    expire_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    /// Short-term key pair for our side
    st: (PublicKey, SecretKey),
    /// This key should be know once session transitions to Ready state.
    client_pk: PublicKey,
    client_lt_pk: Option<PublicKey>,
    state: SessionState,
}

impl Session {
    /// Create new server side session. Only requires client short-term public
    /// key. Server
    /// long-term pair stored in session manager or else where.
    pub fn new(client_pk: PublicKey) -> Session {
        Session {
            expire_at: Utc::now() + Duration::minutes(34),
            created_at: Utc::now(),
            state: SessionState::Fresh,
            st: gen_keypair(),
            client_pk: client_pk,
            client_lt_pk: None,
        }
    }
    /// Verify that session is not expired
    pub fn is_valid(&self) -> bool {
        self.expire_at > Utc::now()
    }

    /// Helper to make a Welcome frame, a reply to Hello frame. Server worflow.
    pub fn make_welcome(&mut self, hello: &Frame, our_sk: &SecretKey) -> LlsdResult<Frame> {
        if self.state != SessionState::Fresh || hello.kind != FrameKind::Hello {
            return Err(LlsdError::InvalidSessionState);
        }
        // Verify content of the box
        if let Ok(payload) = open(&hello.payload, &hello.nonce, &hello.id, our_sk) {
            // We're not going to verify that box content itself, but will verify it's
            // length since
            // that is what matters the most.
            if payload.len() != 256 {
                self.state = SessionState::Error;
                return Err(LlsdError::InvalidHelloFrame);
            }
            let nonce = gen_nonce();
            let welcome_box = seal(self.st.0.as_ref(), &nonce, &hello.id, our_sk);

            let welcome_frame = Frame {
                // Server uses client id in reply.
                id: hello.id,
                nonce: nonce,
                kind: FrameKind::Welcome,
                payload: welcome_box.into(),
            };
            Ok(welcome_frame)
        } else {
            self.state = SessionState::Error;
            Err(LlsdError::DecryptionFailed)
        }
    }
    /// A helper to extract client's permamanet public key from initiate frame
    /// in order to
    /// authenticate client. Authentication happens in another place.
    pub fn validate_initiate(&self, initiate: &Frame) -> LlsdResult<PublicKey> {
        if let Ok(initiate_payload) =
            open(&initiate.payload,
                 &initiate.nonce,
                 &self.client_pk,
                 &self.st.1)
        {
            // TODO: change to != with proper size
            if initiate_payload.len() < 60 {
                return Err(LlsdError::InvalidInitiateFrame);
            }
            // unwrapping here because they only panic when input is shorter than needed.
            let pk = PublicKey::from_slice(&initiate_payload[0..32])
                .expect("Failed to slice pk from payload");
            let v_nonce = Nonce::from_slice(&initiate_payload[32..56])
                .expect("Failed to slice nonce from payload");
            let v_box = &initiate_payload[56..initiate_payload.len()];

            if let Ok(vouch_payload) = open(v_box, &v_nonce, &pk, &self.st.1) {
                let v_pk = PublicKey::from_slice(&vouch_payload).expect("Wrong Size Key!!!");
                if vouch_payload.len() == 32 || v_pk == self.client_pk {
                    return Ok(pk);
                }
            }
        }
        Err(LlsdError::InvalidInitiateFrame)
    }

    /// Helper to make a Ready frame, a reply to Initiate frame. Server
    /// workflow.
    pub fn make_ready(&mut self, initiate: &Frame, client_lt_pk: &PublicKey) -> LlsdResult<Frame> {
        if self.state != SessionState::Fresh || initiate.kind != FrameKind::Initiate {
            return Err(LlsdError::InvalidSessionState);
        }

        // If client spend more than 3 minutes to come up with initiate - fuck him.
        let duration_since = Utc::now().signed_duration_since(self.created_at);
        if duration_since > Duration::minutes(3) {
            return Err(LlsdError::ExpiredSession);
        }
        self.state = SessionState::Ready;
        self.client_lt_pk = Some(*client_lt_pk);
        let (nonce, payload) = self.seal_msg(READY_PAYLOAD);
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

    fn seal_msg(&self, data: &[u8]) -> (Nonce, Bytes) {
        let nonce = gen_nonce();
        let payload = seal(data, &nonce, &self.client_pk, &self.st.1);
        (nonce, payload.into())
    }

    fn read_msg(&self, frame: &Frame) -> LlsdResult<BytesMut> {
        if let Ok(msg) = open(&frame.payload, &frame.nonce, &self.client_pk, &self.st.1) {
            Ok(msg.into())
        } else {
            Err(LlsdError::DecryptionFailed)
        }
    }
}

impl ::std::default::Default for Session {
    fn default() -> Session {
        let (key, _) = gen_keypair();
        Session::new(key)
    }
}
