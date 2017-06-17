extern crate angel_whisper;

use angel_whisper::llsd::frames::Frame;
use angel_whisper::llsd::tokio::WhisperPipelinedProtocol;
use std::io;
use std::net::SocketAddr;
use futures::{Future};
use tokio_core::net::TcpStream;
use tokio_core::reactor::Handle;
use tokio_proto::TcpClient;
use tokio_proto::pipeline::{ClientService};
use tokio_service::Service;

pub struct Client {
    _private: (),
}

pub struct ClientHandle {
    inner: ClientService<TcpStream, WhisperPipelinedProtocol>,
}

impl Client {
    pub fn new() -> Client {
        Client {
            _private: (),
        }
    }

    pub fn connect(self, addr: &SocketAddr, handle: &Handle)
            -> Box<Future<Item = ClientHandle, Error = io::Error>>
    {
        let ret = TcpClient::new(WhisperPipelinedProtocol)
            .connect(addr, handle)
            .map(|c| ClientHandle { inner: c });

        Box::new(ret)
    }
}

impl Service for ClientHandle {
    type Request = Frame;
    type Response = Frame;
    type Error = io::Error;
    type Future = Box<Future<Item = Frame, Error = io::Error>>;

    fn call(&self, req: Frame) -> Box<Future<Item = Frame, Error = io::Error>> {
        Box::new(self.inner.call(req))
    }
}