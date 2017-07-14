use byteorder::BigEndian;
use bytes::{Bytes, BytesMut};
use bytes::BufMut;
use futures::Poll;
use futures::future;
use futures::future::Future;
use llsd::errors::LlsdError;
use llsd::frames::Frame;
use llsd::route::Route;
use llsd::session::KeyPair;
use llsd::session::Sendable;
use llsd::session::client::Session;
use sodiumoxide::crypto::box_::PublicKey;
use std::cell::RefCell;
use std::io;
use std::rc::Rc;

/// See Into<T> from std lib. Created own trait so I can implement it for types
/// that I don't own...like Message from prost trait.
pub trait IntoBytes {
    /// Consume self and return Bytes.
    fn into_bytes(self) -> Bytes;
}

impl IntoBytes for Bytes {
    fn into_bytes(self) -> Bytes {
        self
    }
}

/// See From<T> from std lib. Created own trait so I can implement it for
/// types that I don't own...like Message from prost trait.
pub trait FromBytes {
    /// consume BytesMut and return Self.
    fn from(bytes: BytesMut) -> Self;
}

impl FromBytes for BytesMut {
    fn from(bytes: BytesMut) -> BytesMut {
        bytes
    }
}

impl FromBytes for Bytes {
    fn from(bytes: BytesMut) -> Bytes {
        bytes.freeze()
    }
}

/// Enum to describe what state connection is.
#[derive(PartialEq, Clone, Hash, Eq)]
pub enum ConnectionState {
    /// Has what looks like a valid (not expired and authenticated) session.
    Ready,
    /// Doesn't have session or session expired.
    NotReady,
}
/// Opt-int helper methods for anything that implements engine. It's split into
/// separate trait because of limitations on mocking library.
pub trait EngineSugar {
    /// Sugar coated request_bytes method. The difference is that it takes
    /// anything that implements IntoBytes as request and returns
    /// anything that implements FromBytes.
    fn request<Req: IntoBytes, Res: 'static + FromBytes + Sized>(&mut self,
                                                                 route: Option<Route>,
                                                                 req: Req)
                                                                 -> RequestResult<Res>;
    /// The same as Engine#call, but takes raw payload, returns raw payload and
    /// provide LlsdError instead of io::Error. You can use this the build your
    /// client.
    fn request_bytes(&mut self, route: Option<Route>, payload: Bytes) -> RequestResult<BytesMut> {
        self.request(route, payload)
    }
    /// Create brand new session.
    fn generate_session(&self) -> Session;
    /// Make a call. This call verify that connection is in the right state.
    fn call(&self, req: Frame) -> FutureResponse;
}
impl<T> EngineSugar for T
where
    T: Engine,
{
    fn request<Req: IntoBytes, Res: 'static + FromBytes + Sized>(&mut self,
                                                                 route: Option<Route>,
                                                                 req: Req)
                                                                 -> RequestResult<Res> {
        if self.connection_state() == ConnectionState::Ready {
            let payload = {
                match route {
                    None => req.into_bytes(),
                    Some(r) => {
                        let bytes = req.into_bytes();
                        let mut ret = BytesMut::with_capacity(8 + bytes.len());
                        ret.put_u64::<BigEndian>(r.as_u64());
                        ret.extend(bytes);
                        ret.freeze()
                    }
                }
            };
            let session = self.session().clone();
            let frame = session
                .borrow_mut()
                .make_message(&payload)
                .expect("Failed to create Message Frame");
            let f = self.call_raw(frame)
                .then(move |resp| match resp {
                          Err(e) => future::err(LlsdError::from(e)),
                          Ok(frame) => {
                              let session = session.clone();
                              let payload = session
                                  .borrow_mut()
                                  .read_msg(&frame)
                                  .expect("Failed to read the message");
                              future::ok(Res::from(payload))
                          }
                      });

            RequestResult(Box::new(f))
        } else {
            let err = LlsdError::InvalidSessionState;
            let f = future::err(err);
            RequestResult(Box::new(f))
        }
    }

    fn call(&self, req: Frame) -> FutureResponse {
        if self.connection_state() == ConnectionState::Ready {
            self.call_raw(req)
        } else {
            let err = io::Error::new(io::ErrorKind::Other, "Invalid state");
            let f = future::err(err);
            FutureResponse(Box::new(f))
        }
    }

    fn generate_session(&self) -> Session {
        Session::new(self.server_public_key(), self.our_long_term_keys())
    }
}
/// Engine is the core of client. See module level documentation.
#[derive(Mock)]
pub trait Engine {
    /// Get state of the current connection.
    fn connection_state(&self) -> ConnectionState;
    /// Return reference to session.
    fn session(&mut self) -> Rc<RefCell<Session>>;

    /// Server long term public key.
    fn server_public_key(&self) -> PublicKey;

    /// Return key pair representing out long term keys.
    fn our_long_term_keys(&self) -> KeyPair;

    /// Helper method to authenticate client with the server.
    fn authenticate(&mut self) -> FutureHandshake;

    /// Make a call. This call doesn't take care of handshake and session;
    /// regeneration.
    fn call_raw(&self, req: Frame) -> FutureResponse;
}
/// Future that return by Engine#request method.
pub struct RequestResult<Res: FromBytes + Sized>(Box<Future<Item = Res, Error = LlsdError> + 'static>);
/// Future reprensenting the result of RPC call.
pub struct FutureResponse(Box<Future<Item = Frame, Error = io::Error> + 'static>);
/// Future representing the result of handshake.
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

impl<Res: FromBytes + Sized> Future for RequestResult<Res> {
    type Item = Res;
    type Error = LlsdError;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

/// Tokio backed implementation of client.
#[cfg(feature = "system-on-tokio")]
pub mod tokio {
    use super::{ConnectionState, Engine, EngineSugar, FutureHandshake, FutureResponse};
    use futures;
    use futures::Future;
    use llsd::frames::Frame;
    use llsd::session::{KeyPair, Sendable};
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
        _handle: Handle,
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
                        _handle: handle.clone(),
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
        fn connection_state(&self) -> ConnectionState {
            if let Some(session) = self.session.clone() {
                if session.borrow().can_send() {
                    ConnectionState::Ready
                } else {
                    ConnectionState::NotReady
                }
            } else {
                ConnectionState::NotReady
            }
        }
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
        fn authenticate(&mut self) -> FutureHandshake {
            let service = self.inner.clone();
            let session = self.session();

            let hello_frame = session.borrow().make_hello();
            let hello_request = service.borrow().call(hello_frame);

            let initaite_request = hello_request.and_then(move |hello_response| {
                let initiate_future = {
                    let session_initiate = session.clone();
                    let service_marker = service.clone();
                    let service_initiate = service_marker.borrow();
                    let initiate = session_initiate
                        .borrow_mut()
                        .make_initiate(&hello_response)
                        .unwrap();
                    service_initiate.call(initiate)
                };
                initiate_future.map(move |frame| (session, service, frame))
            });

            let handshake = initaite_request
                .then(move |result| if let Ok((session, _service, initiate_respose)) = result {
                          let ready = session.borrow_mut().read_ready(&initiate_respose);
                          if ready.is_ok() {
                              futures::future::ok(())
                          } else {
                              futures::future::err(io::Error::new(io::ErrorKind::Other,
                                                                  "handshake failed"))
                          }
                      } else {
                          futures::future::err(io::Error::new(io::ErrorKind::Other,
                                                              "handshake failed"))
                      });

            FutureHandshake(Box::new(handshake))
        }

        fn call_raw(&self, req: Frame) -> FutureResponse {
            let service = self.inner.clone();
            let f = service.borrow().call(req);

            FutureResponse(Box::new(f))
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


#[cfg(test)]
mod test {
    use super::{ConnectionState, Engine, EngineSugar, FutureResponse};
    use byteorder::{BigEndian, ByteOrder};
    use bytes::Bytes;
    use futures::{Future, Poll};
    use futures::future;
    use llsd::errors::LlsdError;
    use llsd::frames::Frame;
    use llsd::route::Route;
    use llsd::session::Sendable;
    use llsd::session::client::Session;
    use llsd::session::server::Session as ServerSession;
    use mockers::Scenario;
    use mockers::matchers::ANY;
    use sodiumoxide::crypto::box_::SecretKey;
    use sodiumoxide::crypto::box_::gen_keypair;
    use std::cell::RefCell;
    use std::io;
    use std::rc::Rc;

    fn do_handshake(client_session: &mut Session,
                    server_session: &mut ServerSession,
                    server_lt_secret: &SecretKey) {
        let hello_frame = client_session.make_hello();
        let welcome_frame = server_session
            .make_welcome(&hello_frame, &server_lt_secret).unwrap();

        let initiate_frame = client_session
            .make_initiate(&welcome_frame).unwrap();

        let client_lt_pk = server_session
            .validate_initiate(&initiate_frame).unwrap();

        let ready_frame = server_session
            .make_ready(&initiate_frame, &client_lt_pk).unwrap();
        client_session.read_ready(&ready_frame).unwrap();
    }

    #[test]
    fn request_bytes_not_authenticated() {
        let scenario = Scenario::new();
        let mut engine = scenario.create_mock_for::<Engine>();
        scenario.expect(engine
                            .connection_state_call()
                            .and_return(ConnectionState::NotReady));
        let call_result: Poll<Bytes, LlsdError> = engine.request(None, Bytes::new()).poll();
        assert!(call_result.is_err());
    }

    #[test]
    fn request_bytes_authenticated() {
        let scenario = Scenario::new();
        let mut engine = scenario.create_mock_for::<Engine>();
        let client_lt = gen_keypair();
        let server_lt = gen_keypair();

        let mut client_session = Session::new(server_lt.0.clone(), client_lt.clone());
        let mut server_session = ServerSession::new(client_session.id());
        do_handshake(&mut client_session, &mut server_session, &server_lt.1);
        let session = Rc::new(RefCell::new(client_session));
        scenario.expect(engine
                            .connection_state_call()
                            .and_return(ConnectionState::Ready));
        scenario.expect(engine
                            .call_raw_call(ANY)
                            .and_call(move |req| {
            let server_session = server_session.clone();
            let payload = server_session
                .read_msg(&req).unwrap();
            assert_eq!(payload.len(), 0);

            let resp = server_session
                .make_message(b"well hello").unwrap();
            FutureResponse(Box::new(future::ok(resp)))
        }));
        scenario.expect(engine.session_call().and_return(session));

        let call_result: Poll<Bytes, LlsdError> = engine.request(None, Bytes::new()).poll();
        assert!(call_result.is_ok());
    }


    #[test]
    fn request_bytes_with_route() {
        let scenario = Scenario::new();
        let mut engine = scenario.create_mock_for::<Engine>();
        let client_lt = gen_keypair();
        let server_lt = gen_keypair();

        let mut client_session = Session::new(server_lt.0.clone(), client_lt.clone());
        let mut server_session = ServerSession::new(client_session.id());
        do_handshake(&mut client_session, &mut server_session, &server_lt.1);
        let session = Rc::new(RefCell::new(client_session));

        let route = Route::from("wat");
        let route_copy = route.clone();
        scenario.expect(engine
                            .connection_state_call()
                            .and_return(ConnectionState::Ready));
        scenario.expect(engine
                            .call_raw_call(ANY)
                            .and_call(move |req| {
            let server_session = server_session.clone();
            let payload = server_session
                .read_msg(&req).unwrap();
            assert_eq!(payload.len(), 8);
            let hash = BigEndian::read_u64(&payload);
            let dst = Route::from(hash);
            assert_eq!(dst, route.clone());
            let resp = server_session
                .make_message(b"well hello").unwrap();
            FutureResponse(Box::new(future::ok(resp)))
        }));
        scenario.expect(engine.session_call().and_return(session));

        let call_result: Poll<Bytes, LlsdError> =
            engine.request(Some(route_copy), Bytes::new()).poll();
        assert!(call_result.is_ok());
    }

    #[test]
    fn test_call_not_authenticated() {
        let scenario = Scenario::new();
        let engine = scenario.create_mock_for::<Engine>();
        let (server_lt_pk, _) = gen_keypair();

        scenario.expect(engine
                            .connection_state_call()
                            .and_return(ConnectionState::NotReady));
        scenario.expect(engine
                            .server_public_key_call()
                            .and_return(server_lt_pk.clone()));
        scenario.expect(engine.our_long_term_keys_call().and_return(gen_keypair()));

        let session = engine.generate_session();
        let frame = session.make_hello();
        let call_result: Poll<Frame, io::Error> = engine.call(frame).poll();
        assert!(call_result.is_err());
    }

    #[test]
    fn test_call_authenticated() {
        let scenario = Scenario::new();
        let engine = scenario.create_mock_for::<Engine>();
        let client_lt = gen_keypair();
        let server_lt = gen_keypair();

        let mut client_session = Session::new(server_lt.0.clone(), client_lt.clone());
        let mut server_session = ServerSession::new(client_session.id());
        do_handshake(&mut client_session, &mut server_session, &server_lt.1);
        let session = Rc::new(RefCell::new(client_session));
        let frame = session.borrow().make_message(b"well hello").unwrap();
        let resp_frame = server_session.make_message(b"well hello").unwrap();
        let resp = FutureResponse(Box::new(future::ok(resp_frame)));
        scenario.expect(engine
                            .connection_state_call()
                            .and_return(ConnectionState::Ready));
        scenario.expect(engine.call_raw_call(frame.clone()).and_return(resp));
        let call_result: Poll<Frame, io::Error> = engine.call(frame).poll();
        assert!(call_result.is_ok());

    }
}
