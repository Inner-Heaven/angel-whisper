extern crate angel_whisper;
extern crate bytes;
extern crate tokio_proto;
extern crate tokio_io;
extern crate tokio_core;
extern crate tokio_service;
extern crate futures;
use angel_whisper::{AngelSystem, ClientSession, Sendable};

use angel_whisper::crypto::gen_keypair;
use angel_whisper::frames::FrameKind;
use angel_whisper::system::authenticator::DumbAuthenticator;
use angel_whisper::system::hashmapstore::HashMapStore;

mod support;
use support::service::EchoHandler;

#[test]
fn handshake_and_ping_pong() {
    let (our_pk, our_sk) = gen_keypair();

    let (server_pk, server_sk) = gen_keypair();

    let store = HashMapStore::default();
    let authenticator = DumbAuthenticator::new(vec![our_pk]);

    let system = AngelSystem::new(store,
                                  authenticator,
                                  server_pk,
                                  server_sk,
                                  EchoHandler::default());


    let mut session = ClientSession::new(server_pk, (our_pk, our_sk));
    let hello_result = system.process(session.make_hello());
    assert!(hello_result.is_ok());
    let welcome_frame = hello_result.unwrap();
    assert_eq!(welcome_frame.kind, FrameKind::Welcome);

    let initiate = session.make_initiate(&welcome_frame).unwrap();

    let initiate_result = system.process(initiate);

    assert!(initiate_result.is_ok());
    let ready = initiate_result.unwrap();
    assert_eq!(&ready.kind, &FrameKind::Ready);

    let ready_status = session.read_ready(&ready);
    assert!(ready_status.is_ok());


    let ping_frame = session
        .make_message(&b"ping".to_vec())
        .expect("Failed to create Message Frame");
    let pong_result = system.process(ping_frame);
    assert!(pong_result.is_ok());

    let message_frame = pong_result.unwrap();
    let pong_payload = session.read_msg(&message_frame).unwrap();
    assert_eq!(pong_payload, b"pong".to_vec());

}
