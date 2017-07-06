#![feature(test)]
extern crate angel_whisper;
extern crate bytes;

use angel_whisper::{AngelSystem, ClientSession, Sendable, ServerSession};

use angel_whisper::crypto::gen_keypair;
use angel_whisper::errors::{AWError, AWResult};
use angel_whisper::system::ServiceHub;
use angel_whisper::system::authenticator::DumbAuthenticator;
use angel_whisper::system::hashmapstore::HashMapStore;
use angel_whisper::system::Handler;
use std::sync::{Arc, RwLock};
use bytes::{Bytes, BytesMut};


extern crate test;
use test::Bencher;

pub struct EchoHandler;
    impl Default for EchoHandler {
        fn default() -> EchoHandler {
            EchoHandler {}
        }
    }
    impl Handler for EchoHandler {
        fn handle(&self,
                  _: ServiceHub,
                  _: Arc<RwLock<ServerSession>>,
                  msg: &mut BytesMut)
                  -> AWResult<Bytes> {
            if msg.clone().to_vec() == b"ping".to_vec() {
                Ok(b"pong".to_vec().into())
            } else {
                Err(AWError::NotImplemented)
            }
        }
    }

#[bench]
fn ping_pong_bench(b: &mut Bencher) {
    let (our_pk, our_sk) = gen_keypair();

    let (server_pk, server_sk) = gen_keypair();

    let store = HashMapStore::default();
    let authenticator = DumbAuthenticator::new(vec![our_pk]);

    let system = AngelSystem::new(store, authenticator, server_pk, server_sk, EchoHandler::default());


    let mut session = ClientSession::new(server_pk, (our_pk, our_sk));
    let welcome_frame = system.process(session.make_hello()).unwrap();
    let initiate_frame = session.make_initiate(&welcome_frame).unwrap();
    let ready_frame = system.process(initiate_frame).unwrap();
    let _ = session.read_ready(&ready_frame);
    b.iter(|| {
               let ping_frame = test::black_box(session
                                                    .make_message(&b"ping".to_vec())
                                                    .expect("Failed to create Message Frame"));
               let res = system.process(ping_frame);
               assert!(res.is_ok());
           })
}
