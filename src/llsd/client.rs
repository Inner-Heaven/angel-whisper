use futures::Future;
use llsd::frames::Frame;
use llsd::session::KeyPair;
use llsd::session::client::Session;
use sodiumoxide::crypto::box_::{PublicKey, gen_keypair};
use std::cell::RefCell;
use std::io;
use std::rc::Rc;

/// Engine is the core of client. Meant to be replacable and interchargable, so you can use threaded clients with tokio based servers and vice-versa. This trait also provides some helpers by default.
/// Minimal implementation is `make_async_call()` and `session()`. If client isn't async — just return resolved future in `make_async_all` method.
pub trait Engine {
    /// Make a sync RPC call. Default implementation is calling async and wait for it to complete.
    fn make_call(&self, req: Frame) -> Result<Frame, io::Error> {
        self.make_async_call(req).wait()
    }
    /// Make an async RPC call and return Future.
    /// Please note this implies that future must be scheduled to run before it's returned.
    fn make_async_call(&self, req: Frame) -> Box<Future<Item = Frame, Error = io::Error>>;

    /// Return reference to session.
    fn session(&self) -> Rc<RefCell<Session>>;

    /// Return public key.
    fn server_public_key(&self) -> PublicKey;

    /// Return key pair representing out long term keys.
    fn our_long_term_keys(&self) -> KeyPair;

    /// Helper method to authenticate client with the server. Default implementation uses make_call.
    fn authenticate(&mut self) -> Result<(), io::Error> {
        let session = self.session().clone();

        let hello_frame = session.borrow().make_hello();
        let hello_resp = try!(self.make_call(hello_frame));

        let initiate_frame = session.borrow_mut().make_initiate(&hello_resp).unwrap();
        let initiate_resp = try!(self.make_call(initiate_frame));

        let ready_payload = session.borrow_mut().read_ready(&initiate_resp);
        if let Ok(_is_ready) = ready_payload {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "wat"))
        }
    }

    /// Create brand new session.
    fn generate_session(&self) -> Session {
        let (our_pk, our_sk) = gen_keypair();
        Session::new(self.server_public_key(), self.our_long_term_keys())
    }
}

/// Tokio backed implementation of client.
#[cfg(feature = "system-on-tokio")]
pub mod tokio {
    use futures::Future;
    use llsd::frames::Frame;
    use llsd::session::KeyPair;
    use llsd::session::client::Session;
    use llsd::tokio::WhisperPipelinedProtocol;
    use sodiumoxide::crypto::box_::{PublicKey, gen_keypair};
    use std::cell::RefCell;
    use std::io;
    use std::net::SocketAddr;
    use std::rc::Rc;
    use tokio_core::net::TcpStream;
    use tokio_core::reactor::{Handle, Core};
    use tokio_proto::TcpClient;
    use tokio_proto::pipeline::ClientService;
    use tokio_service::Service;

    /// Pipeline TCP client on top of tokio.
    pub struct TcpPipelineEngine {
        core: Option<Core>,
        handle: Handle,
        inner: ClientService<TcpStream, WhisperPipelinedProtocol>,
        long_term_keys: KeyPair,
        session: Option<Rc<RefCell<Session>>>,
        server_public_key: PublicKey,
    }

    impl Service for TcpPipelineEngine {
        type Request = Frame;
        type Response = Frame;
        type Error = io::Error;
        type Future = Box<Future<Item = Frame, Error = io::Error>>;

        fn call(&self, req: Frame) -> Box<Future<Item = Frame, Error = io::Error>> {
            Box::new(self.inner.call(req))
        }
    }

    impl TcpPipelineEngine {
        /// Create backend for client. This will give engine it's own reactor.
        pub fn new(addr: &SocketAddr, long_term_keys: KeyPair, server_key: PublicKey) -> Self {
            let core = Core::new().expect("Failed to create reactor");
            let handle = core.handle();
            TcpPipelineEngine::create(addr, Some(core), handle, long_term_keys, server_key)
        }
        /// Create backend for the client powered by existing reactor.
        pub fn with_handle(addr: &SocketAddr,
                           handle: Handle,
                           long_term_keys: KeyPair,
                           server_key: PublicKey)
                           -> Self {
            TcpPipelineEngine::create(addr, None, handle, long_term_keys, server_key)
        }

        fn create(addr: &SocketAddr,
                  core: Option<Core>,
                  handle: Handle,
                  long_term_keys: KeyPair,
                  server_key: PublicKey)
                  -> Self {
            let conection_future = TcpClient::new(WhisperPipelinedProtocol).connect(addr, &handle);
            let conection = conection_future
                .wait()
                .expect("Failed to connect to the server");
            TcpPipelineEngine {
                core: core,
                handle: handle,
                inner: conection,
                long_term_keys: long_term_keys,
                server_public_key: server_key,
                session: None,
            }
        }
    }
}
