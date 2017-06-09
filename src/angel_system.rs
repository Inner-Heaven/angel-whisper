use errors::{AWResult, AWErrorKind};

use llsd::frames::{Frame, FrameKind};
use llsd::session::Sendable;
use llsd::session::server::Session;
use sodiumoxide::crypto::box_::{SecretKey, PublicKey};
use std::sync::{Arc, RwLock};
use system::{Handler, ServiceHub};
use system::authenticator::Authenticator;
use system::sessionstore::SessionStore;
use typemap::TypeMap;

pub struct AngelSystem<S: SessionStore, A: Authenticator, H: Handler> {
    sessions: S,
    authenticator: A,
    public_key: PublicKey,
    secret_key: SecretKey,

    services: ServiceHub,
    handler: Arc<H>,
}

impl<S: SessionStore, A: Authenticator, H: Handler> Clone for AngelSystem<S, A, H> {
    fn clone(&self) -> AngelSystem<S, A, H> {
        AngelSystem {
            sessions: self.sessions.clone(),
            authenticator: self.authenticator.clone(),
            public_key: self.public_key,
            secret_key: self.secret_key.clone(),
            services: self.services.clone(),
            handler: self.handler.clone(),
        }
    }
}

impl<S: SessionStore, A: Authenticator, H: Handler> AngelSystem<S, A, H> {
    pub fn new(store: S,
               authenticator: A,
               pk: PublicKey,
               sk: SecretKey,
               handler: H)
               -> AngelSystem<S, A, H> {
        AngelSystem {
            sessions: store,
            authenticator: authenticator,
            public_key: pk,
            secret_key: sk,
            services: Arc::new(RwLock::new(TypeMap::custom())),
            handler: Arc::new(handler),
        }
    }

    pub fn process(&self, req: Frame) -> AWResult<Frame> {
        match req.kind {
            FrameKind::Hello => self.process_hello(&req),
            FrameKind::Initiate => self.process_initiate(&req),
            FrameKind::Message => self.process_message(&req),
            _ => unimplemented!(),
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
                    Err(e) => fail!(AWErrorKind::HandshakeFailed(Some(e))),
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
                                Err(err) => fail!(AWErrorKind::HandshakeFailed(Some(err))),
                            }
                        }
                    }
                } else {
                    // Failed to aquire write lock for a session.
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
        let res = try!(self.handler
                           .handle(self.services.clone(), session_lock.clone(), req.to_vec()));
        let session = match session_lock.read() {
            Err(_) => fail!(AWErrorKind::ServerFault),
            Ok(session) => session,
        };
        session
            .make_message(&res)
            .map_err(|_| AWErrorKind::BadFrame.into())
    }
}


/*
 * System On Tokio
 */

#[cfg(feature = "system-on-tokio")]
pub mod tokio {

    use super::{AngelSystem, Handler, SessionStore, Authenticator, AWErrorKind};
    use frames::Frame;
    use futures::{future, Future, BoxFuture};
    use std::io;
    use std::sync::Arc;
    use tokio_service::Service;

    pub struct InlineService<S: SessionStore, A: Authenticator, H: Handler> {
        system: Arc<AngelSystem<S, A, H>>,
    }

    impl<S: SessionStore, A: Authenticator, H: Handler> Clone for InlineService<S, A, H> {
        fn clone(&self) -> InlineService<S, A, H> {
            InlineService::new(self.system.clone())
        }
    }
    impl<S: SessionStore, A: Authenticator, H: Handler> InlineService<S, A, H> {
        pub fn new(system: Arc<AngelSystem<S, A, H>>) -> InlineService<S, A, H> {
            InlineService { system: system.clone() }
        }
    }

    impl<S: SessionStore, A: Authenticator, H: Handler> Service for InlineService<S, A, H> {
        type Request = Frame;
        type Response = Frame;
        type Error = io::Error;
        type Future = BoxFuture<Self::Response, Self::Error>;

        fn call(&self, req: Self::Request) -> Self::Future {
            match self.system.process(req) {
                Ok(res) => future::ok(res).boxed(),
                Err(err) => {
                    match *err {
                        AWErrorKind::ServerFault => {
                            future::err(io::Error::new(io::ErrorKind::Other, err)).boxed()
                        }
                        _ => unimplemented!(),
                    }
                }
            }
        }
    }
}
