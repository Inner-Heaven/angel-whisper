use std::result::Result;
use blunder::Blunder;

pub type LlsdError = Blunder<LlsdErrorKind>;
pub type LlsdResult<T> = Result<T,LlsdError>;

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
