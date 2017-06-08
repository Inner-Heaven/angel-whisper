

use blunder::Blunder;
use std::convert::{Into, From};
use std::error::Error;
use std::fmt;
use std::io;
use std::result::Result;


pub type LlsdError = Blunder<LlsdErrorKind>;
pub type LlsdResult<T> = Result<T, LlsdError>;


#[derive(Debug, PartialEq, Clone)]
pub enum LlsdErrorKind {
    HandshakeFailed,
    MessageTooBig,
    UnknownClient,
    BadFrame,
    SessionExpired,
    InvalidState,
    IncompleteFrame,
}

impl Error for LlsdErrorKind {
    fn cause(&self) -> Option<&Error> {
        None
    }

    fn description(&self) -> &str {
        match *self {
            _ => "Description not available",
        }
    }
}

impl fmt::Display for LlsdErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl Into<io::Error> for LlsdErrorKind {
    fn into(self) -> io::Error {
        match self {
            LlsdErrorKind::BadFrame => io::Error::new(io::ErrorKind::InvalidData, self),
            _ => io::Error::new(io::ErrorKind::Other, self),
        }
    }
}

impl From<io::Error> for LlsdErrorKind {
    fn from(_error: io::Error) -> LlsdErrorKind {
        LlsdErrorKind::BadFrame
    }
}
