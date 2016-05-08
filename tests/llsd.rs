extern crate angel_whisper;

use angel_whisper::crypto::{PublicKey, SecretKey, gen_keypair};
use angel_whisper::llsd::hashmapstore::HashMapStore;
use angel_whisper::llsd::authenticator::DumbAuthenticator;
use angel_whisper::{AngelSystem, Session, Frame, FrameKind};
use angel_whisper::errors::AWError;


use std::error::Error;

#[test]
fn handshake() {

    let (our_pk, our_sk) = gen_keypair();

    let (server_pk, server_sk) = gen_keypair();

    let store = HashMapStore::new();
    let authenticator = DumbAuthenticator::new(vec![our_pk]);

    let system = AngelSystem::new(store, authenticator, server_pk.clone(), server_sk);


    let session = Session::new(server_pk.clone());

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
    println!("Got error: {:?}\nCause: {:?}", e, e.cause());
}
