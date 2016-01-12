use std::error::Error;
use std::fmt::{Display,Formatter,Result as FmtResult};
use blunder::Blunder;

pub type AWResult<T> = Result<T, AWError>;
pub type AWError = Blunder<AWErrorKind>;

#[derive(Debug, PartialEq)]
pub enum AWErrorKind {
    BadFrame = 1,
    IncorrectState,
    CannotDecrypt,
    NotImplemented,
}

impl Error for AWErrorKind {
    fn description(&self) -> &str {
        match *self {
            AWErrorKind::BadFrame         => "Could not parse frame",
            AWErrorKind::CannotDecrypt    => "Secured payload of the frame cannot be decrypted",
            AWErrorKind::NotImplemented   => "Action not implemented",
            AWErrorKind::IncorrectState   => "Received frame cannot be applies to sesion. For example, sending hello frame when session is in READY state"
        }
    }
}
impl Display for AWErrorKind {
   fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f,"{}", self.description())
    }
}
