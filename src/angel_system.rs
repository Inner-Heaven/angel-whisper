use errors::{AWError, AWResult};

use llsd::errors::LlsdError;
use llsd::frames::{Frame, FrameKind};
use llsd::session::Sendable;
use llsd::session::server::Session;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
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
            _ => unreachable!(),
        }
    }

    fn process_hello(&self, frame: &Frame) -> AWResult<Frame> {
        // Verify it's a new session
        if self.sessions.find_by_pk(&frame.id).is_some() {
            let llsd_error = LlsdError::InvalidSessionState;
            return Err(llsd_error.into());
        }
        let session = Session::new(frame.id);

        // If inserting session failed - bail out early.
        if self.sessions.insert(session).is_none() {
            return Err(AWError::ServerFault);
        }

        if let Some(session_lock) = self.sessions.find_by_pk(&frame.id) {
            let session_guard = session_lock.write();
            if let Ok(mut session) = session_guard {
                let welcome = try!(session.make_welcome(frame, &self.secret_key));
                return Ok(welcome);
            }
        } else {
            return Err(AWError::SessionNotFound);
        }
        Err(AWError::ServerFault)
    }

    // TODO: Rewrite this madness
    fn process_initiate(&self, frame: &Frame) -> AWResult<Frame> {
        match self.sessions.find_by_pk(&frame.id) {
            None => return Err(LlsdError::InvalidSessionState.into()),
            Some(session_lock) => {
                let session_guard = session_lock.write();
                if let Ok(mut session) = session_guard {
                    match session.validate_initiate(frame) {
                        Err(err) => Err(err.into()),
                        Ok(key) => {
                            if !self.authenticator.is_valid(&key) {
                                return Err(AWError::SessionNotFound);
                            }
                            let ready_frame = try!(session.make_ready(frame, &key));
                            Ok(ready_frame)
                        }
                    }
                } else {
                    // Failed to aquire write lock for a session.
                    return Err(AWError::ServerFault);
                }
            }
        }
    }

    fn process_message(&self, frame: &Frame) -> AWResult<Frame> {
        let session_lock = match self.sessions.find_by_pk(&frame.id) {
            None => return Err(LlsdError::InvalidSessionState.into()),
            Some(session_lock) => session_lock,
        };
        let req = {
            let session = match session_lock.read() {
                Err(_) => return Err(AWError::ServerFault),
                Ok(session) => session,
            };
            match session.read_msg(frame) {
                None => return Err(LlsdError::DecryptionFailed.into()),
                Some(req) => req.to_vec(),
            }
        };
        // this is going to take Arc<RWLock<Session>> as argument.
        let res = try!(self.handler
                           .handle(self.services.clone(), session_lock.clone(), req.to_vec()));
        let session = match session_lock.read() {
            Err(_) => return Err(AWError::ServerFault),
            Ok(session) => session,
        };
        session
            .make_message(&res)
            .map_err(|e| e.into()) 
    }
}


/* System On Tokio
 * */

#[cfg(feature = "system-on-tokio")]
pub mod tokio {

    use super::{AngelSystem, Authenticator, Handler, SessionStore};
    use frames::Frame;
    use futures::{BoxFuture, Future, future};
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
                Err(err) => future::err(io::Error::new(io::ErrorKind::Other, err)).boxed()
            }
        }
    }
}
