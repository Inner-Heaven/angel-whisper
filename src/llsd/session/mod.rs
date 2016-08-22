use sodiumoxide::crypto::box_::{PublicKey, SecretKey, Nonce};

use llsd::errors::{LlsdResult, LlsdErrorKind};
use llsd::frames::{Frame, FrameKind};

pub mod client;
pub mod server;
pub type KeyPair = (PublicKey, SecretKey);

/// Array of null bytes used in Hello package. Needs to be bigger than Welcome frame to prevent
/// amplification attacks.
pub static NULL_BYTES: [u8; 256] = [b'\x00'; 256];

/// Session has three states. Each state means different thing on client and server. For example,
/// on client Fresh state means that client has send Hello frame to server. On the server, this
/// means server recieved Hello and replied with Welcome. In case Hello was rejected - server goes
/// into Error state and session is ready to be securely erased by reaper.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    /// This state means that client have sent Hello frame.
    Fresh,
    /// This state means that session is established and messages can be sent both ways.
    Ready,
    /// This state means that session established, but can't be used at the time. Session with this
    /// state would be killed by reaper on next run.
    Error
}


pub trait Sendable {
    fn id(&self) -> PublicKey;

    fn read_msg(&self, frame: &Frame) -> Option<Vec<u8>>;
    fn seal_msg(&self, data: &[u8]) -> (Nonce, Vec<u8>);
    fn can_send(&self) -> bool;

    /// Helper to send a Message Frame.
    fn make_message(&self, data: &[u8]) -> LlsdResult<Frame> {
        if !self.can_send() {
            fail!(LlsdErrorKind::InvalidState)
        }
        let (nonce, payload) = self.seal_msg(data);
        let frame = Frame {
            id: self.id(),
            nonce: nonce,
            kind: FrameKind::Message,
            payload: payload
        };
        Ok(frame)
    }
}
#[cfg(test)]
mod test {
    use sodiumoxide::crypto::box_::{gen_keypair};

    use super::client::Session as ClientSession;
    use super::server::Session as ServerSession;
    use super::Sendable;
    #[test]
    fn test_successful_hashshake() {
        let client_lt = gen_keypair();
        let server_lt = gen_keypair();

        let mut client_session = ClientSession::new(server_lt.0.clone(), client_lt.clone());
        let mut server_session = ServerSession::new(client_session.id());

        let hello_frame = client_session.make_hello();

        let welcome_frame = server_session.make_welcome(&hello_frame, &server_lt.1).expect("Failed to create welcome");

        let initiate_frame = client_session.make_initiate(&welcome_frame).expect("Failed to create initiate");

        assert!(!client_session.can_send());
        assert!(!server_session.can_send());
        let client_lt_pk = server_session.validate_initiate(&initiate_frame).expect("Failed to validate initiate frame");
        assert_eq!(&client_lt_pk, &client_lt.0);

        let ready_frame = server_session.make_ready(&initiate_frame, &client_lt_pk).expect("Failed to create readu frame");


        assert!(client_session.read_ready(&ready_frame).is_ok());
        assert!(client_session.can_send());

        assert!(server_session.can_send());


        // Messages flow around like record
        let from_client_to_server = client_session.make_message(b"Shout it loud and proud").unwrap();
        let from_client_to_server_read = server_session.read_msg(&from_client_to_server).unwrap();
        assert_eq!(&from_client_to_server_read, b"Shout it loud and proud");

        let from_server_to_client = server_session.make_message(b"I'm the hyper star").unwrap();
        let from_server_to_client_read = client_session.read_msg(&from_server_to_client).unwrap();
        assert_eq!(&from_server_to_client_read, b"I'm the hyper star");
    }
}
