use blunder::Blunder;

use llsd::errors::LlsdError;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

pub type AWResult<T> = Result<T, AWError>;
pub type AWError = Blunder<AWErrorKind>;

#[derive(Debug, PartialEq)]
pub enum AWErrorKind {
    BadFrame,
    IncorrectState,
    CannotDecrypt,
    NotImplemented,
    ServerFault,
    HandshakeFailed(Option<LlsdError>),
}

impl Error for AWErrorKind {
    fn description(&self) -> &str {
        match *self {
            AWErrorKind::BadFrame => "Could not parse frame",
            AWErrorKind::CannotDecrypt => "Secured payload of the frame cannot be decrypted",
            AWErrorKind::NotImplemented => "Action not implemented",
            AWErrorKind::IncorrectState => {
                "Received frame cannot be applies to sesion. For example, sending hello frame when \
                 session is in READY state"
            }
            AWErrorKind::ServerFault => "Shit is on fire yo",
            AWErrorKind::HandshakeFailed(_) => "Error during handshake. Wrong key for example",
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            AWErrorKind::HandshakeFailed(Some(ref e)) => Some(e),
            _ => None,
        }
    }
}
impl Display for AWErrorKind {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.description())
    }
}
