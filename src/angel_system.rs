use sodiumoxide::crypto::box_::{SecretKey, PublicKey};
use typemap::TypeMap;
use std::sync::{Arc, RwLock};

use llsd::frames::{Frame, FrameKind};
use llsd::session::server::Session;
use llsd::session::Sendable;
use llsd::sessionstore::SessionStore;
use llsd::authenticator::Authenticator;
use errors::{AWResult, AWErrorKind};
use system::{Handler, ServiceHub};

pub type Response = Vec<u8>;


pub struct AngelSystem<S: SessionStore, A: Authenticator, H: Handler>   {
    sessions: S,
    authenticator: A,
    public_key: PublicKey,
    secret_key: SecretKey,

    services: ServiceHub,
    handler: Arc<H>
}

impl <S: SessionStore, A: Authenticator, H: Handler> Clone for AngelSystem<S,A,H>{
    fn clone(&self) -> AngelSystem<S,A,H> {
        AngelSystem {
            sessions: self.sessions.clone(),
            authenticator: self.authenticator.clone(),
            public_key: self.public_key,
            secret_key: self.secret_key.clone(),
            services: self.services.clone(),
            handler: self.handler.clone()
        }
    }
}

impl <S: SessionStore, A: Authenticator, H: Handler> AngelSystem<S,A,H>{
    pub fn new(store: S, authenticator: A, pk: PublicKey, sk: SecretKey, handler: H) -> AngelSystem<S,A,H> {
        AngelSystem {
            sessions: store,
            authenticator: authenticator,
            public_key: pk,
            secret_key: sk,
            services: Arc::new(RwLock::new(TypeMap::new())),
            handler: Arc::new(handler)
        }
    }

    pub fn process(&self, req: Frame) -> AWResult<Frame> {
        match req.kind {
            FrameKind::Hello    => self.process_hello(&req),
            FrameKind::Initiate => self.process_initiate(&req),
            FrameKind::Message  => self.process_message(&req),
            _                   => unimplemented!()
        }
    }

    fn process_hello(&self, frame: &Frame) -> AWResult<Frame> {
        // Verify it's a new session
        if let Some(_) = self.sessions.find_by_pk(&frame.id) {
            fail!(AWErrorKind::IncorrectState);
        }
        let session = Session::new(frame.id);

        // If inserting session failed - bail out early.
        if let None = self.sessions.insert(session) {
            fail!(AWErrorKind::ServerFault);
        }

        if let Some(session_lock) = self.sessions.find_by_pk(&frame.id) {
            let session_guard = session_lock.write();
            if let Ok(mut session) = session_guard {
                match session.make_welcome(frame, &self.secret_key) {
                    Ok(frame) => return Ok(frame),
                    Err(e)  => fail!(AWErrorKind::HandshakeFailed(Some(e)))
                }
            }
        } else {
            fail!(AWErrorKind::HandshakeFailed(None))
        }
        fail!(AWErrorKind::ServerFault);
    }

    // TODO: Rewrite this madness
    fn process_initiate(&self, frame: &Frame) -> AWResult<Frame> {
        match self.sessions.find_by_pk(&frame.id) {
            None => fail!(AWErrorKind::IncorrectState),
            Some(session_lock) => {
                let session_guard = session_lock.write();
                if let Ok(mut session) = session_guard {
                    match session.validate_initiate(frame) {
                        None => fail!(AWErrorKind::HandshakeFailed(None)),
                        Some(key) => {
                            if !self.authenticator.is_valid(&key) {
                                fail!(AWErrorKind::HandshakeFailed(None));
                            }
                            match session.make_ready(frame, &key) {
                                Ok(res) => Ok(res),
                                Err(err) => fail!(AWErrorKind::HandshakeFailed(Some(err)))
                            }
                        }
                    }
                } else { // Failed to aquire write lock for a session.
                    fail!(AWErrorKind::ServerFault);
                }
            }
        }
    }

    fn process_message(&self, frame: &Frame) -> AWResult<Frame> {
        let session_lock = match self.sessions.find_by_pk(&frame.id) {
            None => fail!(AWErrorKind::IncorrectState),
            Some(session_lock) => session_lock,
        };
        let req = {
            let session = match session_lock.read() {
                Err(_) => fail!(AWErrorKind::ServerFault),
                Ok(session) => session,
            };
            match session.read_msg(frame) {
                None => fail!(AWErrorKind::CannotDecrypt),
                Some(req) => req.to_vec(),
            }
        };
        // this is going to take Arc<RWLock<Session>> as argument.
        let res = try!(self.handler.handle(self.services.clone(), req.to_vec()));
        let session = match session_lock.read() {
            Err(_) => fail!(AWErrorKind::ServerFault),
            Ok(session) => session,
        };
        session.make_message(&res).map_err(|_| AWErrorKind::BadFrame.into())
    }
}
