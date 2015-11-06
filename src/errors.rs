use std::error::Error;
use std::fmt::{Display,Formatter,Result as FmtResult};
use blunder::Blunder;

pub type AWResult<T> = Result<T, AWError>;
pub type AWError = Blunder<AWErrorKind>;

#[derive(Debug, PartialEq)]
pub enum AWErrorKind {
    BadFrame = 1,
    CannotDecrypt,
    NotImplemented,
}

impl Error for AWErrorKind {
    fn description(&self) -> &str {
        match *self {
            AWErrorKind::BadFrame         => "Could not parse frame",
            AWErrorKind::CannotDecrypt    => "Secured payload of the frame cannot be decrypted",
            AWErrorKind::NotImplemented   => "Action not implemented"
        }
    }
}
impl Display for AWErrorKind {
   fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f,"{}", self.description())
    }
}
