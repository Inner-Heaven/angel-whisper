use sodiumoxide::crypto::box_::{SecretKey, PublicKey};

use llsd::frames::{Frame, FrameKind};
use llsd::session::server::Session;
use llsd::sessionstore::SessionStore;
use llsd::authenticator::Authenticator;
use errors::{AWResult, AWErrorKind};

type Response = Vec<u8>;

pub struct AngelSystem<S: SessionStore, A: Authenticator>   {
    sessions: S,
    authenticator: A,
    public_key: PublicKey,
    secret_key: SecretKey
}

impl <S: SessionStore, A: Authenticator> Clone for AngelSystem<S,A>{
    fn clone(&self) -> AngelSystem<S,A> {
        AngelSystem {
            sessions: self.sessions.clone(),
            authenticator: self.authenticator.clone(),
            public_key: self.public_key.clone(),
            secret_key: self.secret_key.clone()
        }
    }
}

impl <S: SessionStore, A: Authenticator> AngelSystem<S,A>{

    pub fn new(store: S, authenticator: A, pk: PublicKey, sk: SecretKey) -> AngelSystem<S,A> {
        AngelSystem {
            sessions: store,
            authenticator: authenticator,
            public_key: pk,
            secret_key: sk
        }
    }

    pub fn process(&self, req: Frame) -> AWResult<Frame> {
        match req.kind {
            FrameKind::Hello => self.process_hello(&req),
            _                => unimplemented!()
        }
    }

    fn process_hello(&self, frame: &Frame) -> AWResult<Frame> {
        // Verify it's a new session
        if let Some(_) = self.sessions.find_by_pk(&frame.id) {
            println!("wat");
            fail!(AWErrorKind::IncorrectState);
        }
        let session = Session::new(frame.id.clone());
        println!("Session in System: {:?}", session);
        self.sessions.insert(session);
        let wat = self.sessions.find_by_pk(&frame.id);
        println!("Frame: {:?}\nSession:{:?}", frame, wat);
        if let Some(session_lock) = self.sessions.find_by_pk(&frame.id) {
            println!("lookup");
            let session_guard = session_lock.write();
            if let Ok(mut session) = session_guard {
                match session.make_welcome(&frame, &self.secret_key) {
                    Ok(frame) => return Ok(frame),
                    Err(e)  => fail!(AWErrorKind::HandshakeFailed(Some(e)))
                }
            }
        }
        fail!(AWErrorKind::ServerFault);
    }
}
