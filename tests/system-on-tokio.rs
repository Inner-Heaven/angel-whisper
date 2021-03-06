#[cfg(feature = "system-on-tokio")]

extern crate angel_whisper;
extern crate tokio_proto;
extern crate tokio_io;
extern crate tokio_core;
extern crate tokio_service;
extern crate futures;
extern crate bytes;

use angel_whisper::{AngelSystem, ClientSession, Sendable};
use angel_whisper::angel_system::tokio::InlineService;

use angel_whisper::crypto::gen_keypair;
use angel_whisper::llsd::client::Engine;
use angel_whisper::llsd::client::tokio::TcpPipelineEngine;
use angel_whisper::llsd::tokio::WhisperPipelinedProtocol;
use angel_whisper::system::authenticator::DumbAuthenticator;
use angel_whisper::system::hashmapstore::HashMapStore;
use angel_whisper::tokio::Core;
use angel_whisper::tokio::Service;
use std::sync::Arc;
use std::thread;
use tokio_proto::TcpServer;

mod support;

use support::client::Client;
use support::service::EchoHandler;

#[test]
fn test_pipeline_framed_server_compiles() {
    let (our_pk, _our_sk) = gen_keypair();

    let (server_pk, server_sk) = gen_keypair();

    let store = HashMapStore::default();
    let authenticator = DumbAuthenticator::new(vec![our_pk]);

    let system = Arc::new(AngelSystem::new(store,
                                           authenticator,
                                           server_pk,
                                           server_sk,
                                           EchoHandler::default()));

    // Test we can use Framed from tokio-core for (simple) streaming pipeline
    // protocols
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
                                           server_pk,
                                           server_sk,
                                           EchoHandler::default()));
    let service = InlineService::new(system);

    let mut session = ClientSession::new(server_pk, (our_pk, our_sk));

    // spin new reactor core;
    let mut lp = Core::new().unwrap();

    // spin new server on local host
    let addr = "127.0.0.1:12345".parse().unwrap();

    thread::spawn(move || {
                      TcpServer::new(WhisperPipelinedProtocol, addr)
                          .serve(move || Ok(service.clone()));
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

#[test]
fn test_tokio_client_engine() {
    let (our_pk, our_sk) = gen_keypair();

    let (server_pk, server_sk) = gen_keypair();

    let store = HashMapStore::default();
    let authenticator = DumbAuthenticator::new(vec![our_pk]);

    let system = Arc::new(AngelSystem::new(store,
                                           authenticator,
                                           server_pk,
                                           server_sk,
                                           EchoHandler::default()));
    let service = InlineService::new(system);

    // spin new reactor core;
    let mut core = Core::new().expect("Failed to create reactor [thread]");


    // spin new server on local host
    let addr = "127.0.0.1:12356".parse().unwrap();

    thread::spawn(move || {
                      TcpServer::new(WhisperPipelinedProtocol, addr)
                          .serve(move || Ok(service.clone()));
                  });



    let duration = std::time::Duration::from_millis(13);
    thread::sleep(duration);
    let client_future =
        TcpPipelineEngine::connect(&addr, core.handle(), (our_pk, our_sk.clone()), server_pk);
    let mut client = core.run(client_future).expect("failed to connect");

    let handshake_future = client.authenticate();

    let handshake_result = core.run(handshake_future);

    assert!(handshake_result.is_ok());
    let session = client.session();
    let ping_frame = session
        .borrow()
        .make_message(&b"ping".to_vec())
        .expect("Failed to create Message Frame");

    let ping = client.call_raw(ping_frame);
    let pong = core.run(ping).unwrap();

    let pong_payload = session.borrow().read_msg(&pong).unwrap();
    assert_eq!(pong_payload, b"pong".to_vec());
}
