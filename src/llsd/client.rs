use llsd::frames::Frame;
use llsd::session::KeyPair;
use llsd::session::client::Session;
use sodiumoxide::crypto::box_::PublicKey;
use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use futures::future::Future;

/// shortcut for futures that are returned by `Engine`.
pub type EngineFuture = Box<Future<Item = Frame, Error = io::Error>>;

/// Engine is the core of client.
pub trait Engine {
    /// Make a RPC call to remote server.
    fn make_call(&self, req: Frame) -> Result<Frame, io::Error>;

    /// Create Future for RPC call. Result of this function must be submited to reactor.
    fn create_call(&self, req: Frame) -> EngineFuture;

    /// Return reference to session.
    fn session(&mut self) -> Rc<RefCell<Session>>;

    /// Return public key.
    fn server_public_key(&self) -> PublicKey;

    /// Return key pair representing out long term keys.
    fn our_long_term_keys(&self) -> KeyPair;

    /// Helper method to authenticate client with the server.
    fn authenticate(&mut self) -> Result<(), io::Error> {
        let session = self.session().clone();

        let hello_frame = session.borrow().make_hello();
        let hello_resp = (self.make_call(hello_frame))?;

        let initiate_frame = session.borrow_mut().make_initiate(&hello_resp).unwrap();
        let initiate_resp = (self.make_call(initiate_frame))?;

        let ready_payload = session.borrow_mut().read_ready(&initiate_resp);
        if let Ok(_is_ready) = ready_payload {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "wat"))
        }
    }

    /// Create brand new session.
    fn generate_session(&self) -> Session {
        Session::new(self.server_public_key(), self.our_long_term_keys())
    }
}

/// Tokio backed implementation of client.
#[cfg(feature = "system-on-tokio")]
pub mod tokio {
    use futures;
    use futures::Future;
    use llsd::frames::Frame;
    use llsd::session::KeyPair;
    use llsd::session::client::Session;
    use llsd::tokio::WhisperPipelinedProtocol;
    use super::{EngineFuture, Engine};
    use sodiumoxide::crypto::box_::PublicKey;
    use std::cell::RefCell;
    use std::io;
    use std::net::SocketAddr;
    use std::rc::Rc;
    use std::thread;
    use tokio_core::net::TcpStream;
    use tokio_core::reactor::{Handle, Core};
    use tokio_proto::TcpClient;
    use tokio_proto::pipeline::ClientService;
    use tokio_service::Service;


    type ShutdownSignal = futures::sync::oneshot::Sender<()>;

    /// Pipeline TCP client on top of tokio.
    pub struct TcpPipelineEngine {
        _shutdown_channel: Option<ShutdownSignal>,
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
        type Future = EngineFuture;

        fn call(&self, req: Frame) -> Box<Future<Item = Frame, Error = io::Error>> {
            Box::new(self.inner.call(req))
        }
    }

    impl TcpPipelineEngine {
        /// Create backend for client. This will give engine it's own reactor.
        pub fn new(addr: &SocketAddr, long_term_keys: KeyPair, server_key: PublicKey) -> Self {
            let (tx, rx) = futures::oneshot();
            let (tx_shutdown, rx_shutdown) = futures::oneshot();

            thread::spawn(move || {
                              let mut core = Core::new().expect("Failed to create reactor");
                              let response = tx.send(core.remote());
                              response.expect("Failed to send handle.");
                              let _done = core.run(rx_shutdown);
                          });

            let remote = rx.wait().expect("Failed to create new reactor");
            let handle = remote.handle().expect("Failed to create new reactor");
            TcpPipelineEngine::create(addr, Some(tx_shutdown), handle, long_term_keys, server_key)
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
                  shutdown_channel: Option<ShutdownSignal>,
                  handle: Handle,
                  long_term_keys: KeyPair,
                  server_key: PublicKey)
                  -> Self {
            let connection_future = TcpClient::new(WhisperPipelinedProtocol).connect(addr, &handle);
            let connection = connection_future
                .wait()
                .expect("Failed to connect to the server");
            TcpPipelineEngine {
                _shutdown_channel: shutdown_channel,
                handle: handle,
                inner: connection,
                long_term_keys: long_term_keys,
                server_public_key: server_key,
                session: None,
            }
        }
        
        /// Execute given future on whatever reactor is assigned to this client.
        pub fn execute(&self, future: EngineFuture) -> Result<Frame, io::Error> {
                      let (tx, rx) = futures::oneshot();

            let call = future.then(|resp| {
                          let _ = tx.send(resp);
                          Ok(())
                      });

            self.handle.spawn(call);

            rx.wait().expect("Someone canceled future")
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
            self.server_public_key
        }

        fn our_long_term_keys(&self) -> KeyPair {
            self.long_term_keys.clone()
        }
        fn make_call(&self, req: Frame) -> Result<Frame, io::Error> {
            let call = self.inner.call(req);
            self.execute(Box::new(call))
        }

        fn create_call(&self, req: Frame) -> Box<Future<Item = Frame, Error= io::Error>> {
            Box::new(self.inner.call(req))
        }
    }
    #[cfg(test)]
    mod test {
        use super::*;

        use ::crypto::gen_keypair;

        #[test]
        fn without_handler_compiles() {
            if false {
                let pair = gen_keypair();
                let (key, _) = gen_keypair();

                let addr = "0.0.0.0:12345".parse().unwrap();

                let _client = TcpPipelineEngine::new(&addr, pair, key);
            }
        }

        #[test]
        fn with_handler_compiles() {
            if false {
                let core = Core::new().unwrap();
                let pair = gen_keypair();
                let (key, _) = gen_keypair();

                let addr = "0.0.0.0:12345".parse().unwrap();

                let _client = TcpPipelineEngine::with_handle(&addr, core.handle(), pair, key);
            }
        }
    }
}
