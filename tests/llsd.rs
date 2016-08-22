extern crate angel_whisper;

use angel_whisper::crypto::gen_keypair;
use angel_whisper::llsd::hashmapstore::HashMapStore;
use angel_whisper::llsd::authenticator::DumbAuthenticator;
use angel_whisper::{AngelSystem, ClientSession, FrameKind};
use angel_whisper::errors::AWError;


use std::error::Error;

#[test]
fn handshake() {
    print!("!!! STARTING HASHSHAKE TEST !!!");
    let (our_pk, our_sk) = gen_keypair();

    let (server_pk, server_sk) = gen_keypair();

    let store = HashMapStore::default();
    let authenticator = DumbAuthenticator::new(vec![our_pk]);

    let system = AngelSystem::new(store, authenticator, server_pk.clone(), server_sk);


    let session = ClientSession::new(server_pk.clone(), (our_pk, our_sk));

    println!("client_session = {:#?}", session);
    match system.process(session.make_hello()) {
        Ok(frame) => assert_eq!(frame.kind, FrameKind::Welcome),
        Err(e) => {
            print_error(e);
            panic!("Server didn't respond with welcome");
        }
    }

    assert_eq!(4, 4);
}


fn print_error(e: AWError) {
    println!("Got error:\n{:#?}\nCause: {:#?}", e, e.cause());
}
