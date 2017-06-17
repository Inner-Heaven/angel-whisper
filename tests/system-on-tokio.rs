#[cfg(feature = "system-on-tokio")]

extern crate angel_whisper;
#[macro_use]
extern crate blunder;
extern crate tokio_proto;
extern crate tokio_io;
extern crate tokio_core;
extern crate tokio_service;
extern crate futures;

use angel_whisper::{AngelSystem, ClientSession, ServerSession, Sendable};
use angel_whisper::angel_system::tokio::InlineService;

use angel_whisper::crypto::gen_keypair;
use angel_whisper::errors::{AWResult, AWErrorKind};
use angel_whisper::llsd::tokio::WhisperPipelinedProtocol;
use angel_whisper::system::{ServiceHub};
use angel_whisper::system::authenticator::DumbAuthenticator;
use angel_whisper::system::hashmapstore::HashMapStore;
use std::sync::{Arc, RwLock};
use tokio_proto::TcpServer;
use angel_whisper::tokio::Core;
use angel_whisper::tokio::Service;
use std::thread;

mod support;

use support::client::Client;

fn ping_pong(_: ServiceHub, _: Arc<RwLock<ServerSession>>, msg: Vec<u8>) -> AWResult<Vec<u8>> {
    if msg == b"ping".to_vec() {
        Ok(b"pong".to_vec())
    } else {
        fail!(AWErrorKind::BadFrame);
    }
}

#[test]
fn test_pipeline_framed_server_compiles() {
    let (our_pk, _our_sk) = gen_keypair();

    let (server_pk, server_sk) = gen_keypair();

    let store = HashMapStore::default();
    let authenticator = DumbAuthenticator::new(vec![our_pk]);

    let system = Arc::new(AngelSystem::new(store,
                                           authenticator,
                                           server_pk.clone(),
                                           server_sk,
                                           ping_pong));

    // Test we can use Framed from tokio-core for (simple) streaming pipeline protocols
    // Don't want this to run, only compile
    if false {
        let service = InlineService::new(system);
        let addr = "0.0.0.0:12345".parse().unwrap();
        TcpServer::new(WhisperPipelinedProtocol, addr).serve(move || Ok(service.clone()));
    }
}

#[test]
fn test_ping_pong() {
    let (our_pk, our_sk) = gen_keypair();

    let (server_pk, server_sk) = gen_keypair();

    let store = HashMapStore::default();
    let authenticator = DumbAuthenticator::new(vec![our_pk]);

    let system = Arc::new(AngelSystem::new(store,
                                           authenticator,
                                           server_pk.clone(),
                                           server_sk,
                                           ping_pong));
    let service = InlineService::new(system);

    let mut session = ClientSession::new(server_pk.clone(), (our_pk, our_sk));
    
    // spin new reactor core;
    let mut lp = Core::new().unwrap();
    
    // spin new server on local host
    let addr = "127.0.0.1:12345".parse().unwrap();

    thread::spawn(move || {
        TcpServer::new(WhisperPipelinedProtocol, addr).serve(move || Ok(service.clone()));
    });



    let duration = std::time::Duration::from_millis(13);
    thread::sleep(duration);

    let client_future = Client::new().connect(&addr, &lp.handle());
    let client = lp.run(client_future).unwrap();

    let welcome_request = client.call(session.make_hello());
    let welcome_response = lp.run(welcome_request).unwrap();

    let initiate_request = client.call(session.make_initiate(&welcome_response).unwrap());
    let initiate_response = lp.run(initiate_request).unwrap();

    let ready_status = session.read_ready(&initiate_response);
    assert!(ready_status.is_ok());

    let ping_frame = session
        .make_message(&b"ping".to_vec())
        .expect("Failed to create Message Frame");

    let ping = client.call(ping_frame);
    let pong = lp.run(ping).unwrap();

    let pong_payload = session.read_msg(&pong).unwrap();
    assert_eq!(pong_payload, b"pong".to_vec());
}
