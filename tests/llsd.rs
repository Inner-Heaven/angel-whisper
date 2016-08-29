extern crate angel_whisper;
#[macro_use] extern crate blunder;

use angel_whisper::crypto::gen_keypair;
use angel_whisper::llsd::hashmapstore::HashMapStore;
use angel_whisper::llsd::authenticator::DumbAuthenticator;
use angel_whisper::{AngelSystem, ClientSession, Sendable};
use angel_whisper::frames::FrameKind;
use angel_whisper::errors::{AWResult, AWErrorKind};
use angel_whisper::system::ServiceHub;

fn ping_pong(_: ServiceHub, msg: Vec<u8>) -> AWResult<Vec<u8>> {
    if msg == b"ping".to_vec() {
        Ok(b"pong".to_vec())
    } else {
        fail!(AWErrorKind::BadFrame);
    }
}


#[test]
fn handshake_and_ping_pong() {
    let (our_pk, our_sk) = gen_keypair();

    let (server_pk, server_sk) = gen_keypair();

    let store = HashMapStore::default();
    let authenticator = DumbAuthenticator::new(vec![our_pk]);

    let system = AngelSystem::new(store, authenticator, server_pk.clone(), server_sk, ping_pong);


    let mut session = ClientSession::new(server_pk.clone(), (our_pk, our_sk));
    let hello_result = system.process(session.make_hello());
    assert!(hello_result.is_ok());
    let welcome_frame = hello_result.unwrap();
    assert_eq!(welcome_frame.kind, FrameKind::Welcome);

    let initiate = session.make_initiate(&welcome_frame).unwrap();

    let initiate_result = system.process(initiate);

    assert!(initiate_result.is_ok());
    assert_eq!(initiate_result.unwrap().kind, FrameKind::Ready);

    let ping_frame = session.make_message(&b"ping".to_vec()).expect("Failed to create Message Frame");
    let pong_result = system.process(ping_frame);
}
