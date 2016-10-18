#![feature(test)]
extern crate angel_whisper;
#[macro_use] extern crate blunder;

use std::sync::{Arc, RwLock};

use angel_whisper::crypto::gen_keypair;
use angel_whisper::llsd::hashmapstore::HashMapStore;
use angel_whisper::llsd::authenticator::DumbAuthenticator;
use angel_whisper::{AngelSystem, ClientSession, ServerSession, Sendable};
use angel_whisper::frames::FrameKind;
use angel_whisper::errors::{AWResult, AWErrorKind};
use angel_whisper::system::ServiceHub;



extern crate test;
use test::Bencher;

fn ping_pong(_: ServiceHub, _: Arc<RwLock<ServerSession>>, msg: Vec<u8>) -> AWResult<Vec<u8>> {
    if msg == b"ping".to_vec() {
        Ok(b"pong".to_vec())
    } else {
        fail!(AWErrorKind::BadFrame);
    }
}

#[bench]
fn ping_pong_bench(b: &mut Bencher) {
    let (our_pk, our_sk) = gen_keypair();

    let (server_pk, server_sk) = gen_keypair();

    let store = HashMapStore::default();
    let authenticator = DumbAuthenticator::new(vec![our_pk]);

    let system = AngelSystem::new(store, authenticator, server_pk.clone(), server_sk, ping_pong);


    let mut session = ClientSession::new(server_pk.clone(), (our_pk, our_sk));
    let welcome_frame  = system.process(session.make_hello()).unwrap();
    let initiate_frame = session.make_initiate(&welcome_frame).unwrap();
    let ready_frame = system.process(initiate_frame).unwrap();
    session.read_ready(&ready_frame);
    b.iter(|| {
        let ping_frame = test::black_box(session.make_message(&b"ping".to_vec()).expect("Failed to create Message Frame"));
        system.process(ping_frame);
    })
}
