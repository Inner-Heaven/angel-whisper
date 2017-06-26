

use futures::{future, Poll};
use futures::future::Future;
use llsd::frames::Frame;
use llsd::session::KeyPair;
use llsd::session::client::Session;
use sodiumoxide::crypto::box_::PublicKey;
use std::cell::RefCell;
use std::io;
use std::rc::Rc;

/// Engine is the core of client.
pub trait Engine {
    /// Return reference to session.
    fn session(&mut self) -> Rc<RefCell<Session>>;

    /// Return public key.
    fn server_public_key(&self) -> PublicKey;

    /// Return key pair representing out long term keys.
    fn our_long_term_keys(&self) -> KeyPair;

    /// Helper method to authenticate client with the server.
    fn authenticate(&mut self) -> FutureHandshake;

    /// Create brand new session.
    fn generate_session(&self) -> Session {
        Session::new(self.server_public_key(), self.our_long_term_keys())
    }
}

pub struct FutureResponse(Box<Future<Item = Frame, Error = io::Error> + 'static>);
pub struct FutureHandshake(Box<Future<Item = (), Error = io::Error> + 'static>);

impl Future for FutureResponse {
    type Item = Frame;
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

impl Future for FutureHandshake {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

/// Tokio backed implementation of client.
#[cfg(feature = "system-on-tokio")]
pub mod tokio {
    use super::{Engine, FutureHandshake, FutureResponse};
    use futures;
    use futures::Future;
    use futures::IntoFuture;
    use llsd::frames::Frame;
    use llsd::session::KeyPair;
    use llsd::session::client::Session;
    use llsd::tokio::WhisperPipelinedProtocol;
    use sodiumoxide::crypto::box_::PublicKey;
    use std::cell::RefCell;
    use std::io;
    use std::net::SocketAddr;
    use std::rc::Rc;
    use tokio_core::net::TcpStream;
    use tokio_core::reactor::Handle;
    use tokio_proto::TcpClient;
    use tokio_proto::pipeline::ClientService;
    use tokio_service::Service;



    /// Pipeline TCP client on top of tokio.
    pub struct TcpPipelineEngine {
        handle: Handle,
        inner: Rc<RefCell<ClientService<TcpStream, WhisperPipelinedProtocol>>>,
        long_term_keys: KeyPair,
        session: Option<Rc<RefCell<Session>>>,
        server_public_key: PublicKey,
    }


    impl TcpPipelineEngine {
        /// Create backend for the client powered by existing reactor.
        pub fn connect(addr: &SocketAddr,
                       handle: Handle,
                       long_term_keys: KeyPair,
                       server_key: PublicKey)
                       -> Box<Future<Item = Self, Error = io::Error>> {
            let ret = TcpClient::new(WhisperPipelinedProtocol)
                .connect(addr, &handle)
                .map(move |connection| {
                    TcpPipelineEngine {
                        handle: handle.clone(),
                        inner: Rc::new(RefCell::new(connection)),
                        long_term_keys: long_term_keys,
                        server_public_key: server_key,
                        session: None,
                    }
                });
            Box::new(ret)
        }
    }

    impl Engine for TcpPipelineEngine {
        fn session(&mut self) -> Rc<RefCell<Session>> {
            let s = self.session.clone();
            if let Some(session) = s {
                session
            } else {
                let new_session = self.generate_session();
                let cell = Rc::new(RefCell::new(new_session));
                self.session = Some(cell.clone());
                cell
            }
        }

        fn server_public_key(&self) -> PublicKey {
            self.server_public_key.clone()
        }

        fn our_long_term_keys(&self) -> KeyPair {
            self.long_term_keys.clone()
        }
        fn authenticate(&mut self) -> FutureHandshake {
            let service = self.inner.clone();
            let session = self.session();

            let hello_frame = session.borrow().make_hello();
            let hello_request = service.borrow().call(hello_frame);

            let initaite_request = hello_request.and_then(move |hello_response| {
                let initiate_future = {
                    let session_initiate = session.clone();
                    let service_initiate = service.clone();
                    let initiate = session_initiate
                        .borrow_mut()
                        .make_initiate(&hello_response)
                        .unwrap();
                    service_initiate.borrow().call(initiate)
                };
                initiate_future.map(move |frame| (session, service, frame))
            });

            let handshake = initaite_request.then(move |response| {
                let (session, service, initiate_respose) = response.unwrap();
                let ready = session.borrow_mut().read_ready(&initiate_respose);
                if ready.is_ok() {
                    futures::future::ok(())
                } else {
                    futures::future::err(io::Error::new(io::ErrorKind::Other, "handshake failed"))
                }
            });

            FutureHandshake(Box::new(handshake))
        }
    }
    #[cfg(test)]
    mod test {
        use super::*;

        use crypto::gen_keypair;
        use tokio_core::reactor::Core;

        #[test]
        fn with_handler_compiles() {
            if false {
                let core = Core::new().unwrap();
                let pair = gen_keypair();
                let (key, _) = gen_keypair();

                let addr = "0.0.0.0:12345".parse().unwrap();

                let _client = TcpPipelineEngine::connect(&addr, core.handle(), pair, key);
            }
        }
    }
}
