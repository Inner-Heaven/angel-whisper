use sodiumoxide::crypto::box_::{SecretKey, PublicKey};

use llsd::request::{Request, RequestHeader, RequestPayload};
use llsd::sessionstore::SessionStore;
use llsd::authenticator::Authenticator;
use errors::{AWResult, AWError};

type Response = Vec<u8>;

struct AngelSystem<S: SessionStore, A: Authenticator>   {
    sessions: S,
    authenticator: A,
    public_key: PublicKey,
    secret_key: SecretKey
}

impl Clone for AngelSystem {
    fn clone(&self) -> AngelSystem {
        AngelSystem {
            sessions: self.sessions.clone(),
            authenticator: self.authenticator.clone(),
            public_key: self.public_key.clone(),
            secret_key: self.secret_key.clone()
        }
    }
}

impl AngelSystem {
    pub fn process(&self, req: Request) -> AWResult<Response> {
        unimplemented!();
    }

    fn process_hello(&self, frame: &Request) -> AWResult<Response> {
        if let Some(_) = self.sessions.insert(&frame.pk) {
            fail!(AWError::IncorrectState)
        } else {
            unimplemented!();
        }
    }
}
