#[cfg(feature = "system-on-tokio")]

extern crate angel_whisper;
#[macro_use]
extern crate blunder;
extern crate tokio_proto;

use angel_whisper::{AngelSystem, ClientSession, ServerSession, Sendable};
use angel_whisper::angel_system::tokio::InlineService;

use angel_whisper::crypto::gen_keypair;
use angel_whisper::errors::{AWResult, AWErrorKind};
use angel_whisper::frames::FrameKind;
use angel_whisper::llsd::tokio::WhisperPipelinedProtocol;
use angel_whisper::system::{ServiceHub, Handler};
use angel_whisper::system::authenticator::DumbAuthenticator;
use angel_whisper::system::hashmapstore::HashMapStore;
use angel_whisper::system::authenticator::Authenticator;
use angel_whisper::system::sessionstore::SessionStore;
use angel_whisper::crypto::{PublicKey, SecretKey};
use std::sync::{Arc, RwLock};
use tokio_proto::TcpServer;


fn ping_pong(_: ServiceHub, _: Arc<RwLock<ServerSession>>, msg: Vec<u8>) -> AWResult<Vec<u8>> {
    if msg == b"ping".to_vec() {
        Ok(b"pong".to_vec())
    } else {
        fail!(AWErrorKind::BadFrame);
    }
}

#[test]
fn test_streaming_pipeline_framed() {
    let (our_pk, our_sk) = gen_keypair();

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

}
