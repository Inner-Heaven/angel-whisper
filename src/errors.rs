#![allow(missing_docs)]

use llsd::errors::LlsdError;
use std::io;

pub type AWResult<T> = Result<T, AWError>;

quick_error! {
    #[derive(Debug)]
    pub enum AWError {
        Io(err: io::Error) {
            from()
            cause(err)
            description("Underlying I/O error.")
            display("I/O error: {}", err)
        }
        LlsdError(err: LlsdError) {
            from()
            cause(err)
            description("Underlying LLSD error.")
            display("LLSD error: {}", err)
        }
        NotImplemented {
            description("Action not implemented.")
        }
        ServerFault {
            description("Server enoutered an error that it can't recover from.")
        }
        InvalidRoute {}
        SessionNotFound {}
    }
}