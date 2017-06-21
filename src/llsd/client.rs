use futures::Future;
use llsd::frames::Frame;
use llsd::session::client::Session;
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
}

/// Tokio backed implementation of client.
#[cfg(feature = "system-on-tokio")]
pub mod tokio {
    use futures::Future;
    use llsd::frames::Frame;
    use llsd::tokio::WhisperPipelinedProtocol;
    use std::io;
    use std::net::SocketAddr;
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
        pub fn new(addr: &SocketAddr) -> Self {
            let core = Core::new().expect("Failed to create reactor");
            let handle = core.handle();
            let conection_future = TcpClient::new(WhisperPipelinedProtocol)
                .connect(addr, &core.handle());
            let conection = conection_future
                .wait()
                .expect("Failed to connect to the server");
            TcpPipelineEngine {
                core: Some(core),
                handle: handle,
                inner: conection,
            }
        }
        /// Create backend for the client powered by existing reactor.
        pub fn with_handle(addr: &SocketAddr, handle: Handle) -> Self {
            let conection_future = TcpClient::new(WhisperPipelinedProtocol).connect(addr, &handle);
            let conection = conection_future
                .wait()
                .expect("Failed to connect to the server");
            TcpPipelineEngine {
                core: None,
                handle: handle,
                inner: conection,
            }
        }
    }
}
