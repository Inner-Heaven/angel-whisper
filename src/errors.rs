use std::error::Error;
use std::fmt::{Display,Formatter,Result};
use blunder::Blunder;

pub type AWServerError = Blunder<AWServerErrorKind>;

#[derive(Debug, PartialEq)]
pub enum AWServerErrorKind {
    BadFrame = 1,
    CannotDecrypt,
    NotImplemented,
}

impl Error for AWServerErrorKind {
    fn description(&self) -> &str {
        match *self {
            AWServerErrorKind::BadFrame         => "Frame didn't match specification",
            AWServerErrorKind::CannotDecrypt    => "Secured payload of the frame cannot be decrypted",
            AWServerErrorKind::NotImplemented   => "Action not implemented"
        }
    }
}
impl Display for AWServerErrorKind {
   fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f,"{}", self.description())
    }
}
