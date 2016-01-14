use std::result::Result;
use std::error::Error;
use std::fmt;

use blunder::Blunder;


pub type LlsdError = Blunder<LlsdErrorKind>;
pub type LlsdResult<T> = Result<T,LlsdError>;


#[derive(Debug, PartialEq)]
pub enum LlsdErrorKind {
    AuthenticationFailed,
    MessageTooBig,
    DecryptionFailed,
    UnknownClient,
    UnknownFrameKind,
    IncorectSize,
    SessionExpired,
    InvalidState
}

impl Error for LlsdErrorKind {
    fn cause(&self) -> Option<&Error> {
        None
    }

    fn description(&self) -> &str {
        match *self {
            _ => "Description not available"
        }
    }
}

impl fmt::Display for LlsdErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}", self.description())
    }
}
