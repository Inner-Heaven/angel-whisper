use sodiumoxide::crypto::box_::PublicKey;
use std::sync::Arc;

/// Used to authenticate user by his long term public key. This way its easy to
/// test.
pub trait Authenticator: Clone + Send + Sync {
    /// Well...
    fn is_valid(&self, key: &PublicKey) -> bool;
}

/// Authenticator example that is very dumb, but great for testing
pub struct DumbAuthenticator {
    white_list: Arc<Vec<PublicKey>>,
}

impl Clone for DumbAuthenticator {
    fn clone(&self) -> DumbAuthenticator {
        DumbAuthenticator { white_list: self.white_list.clone() }
    }
}

impl DumbAuthenticator {
    pub fn new(keys: Vec<PublicKey>) -> DumbAuthenticator {
        DumbAuthenticator { white_list: Arc::new(keys) }
    }
}

impl Authenticator for DumbAuthenticator {
    fn is_valid(&self, key: &PublicKey) -> bool {
        self.white_list.contains(key)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sodiumoxide::crypto::box_;

    #[test]
    fn test_dumb_store() {
        let (pk, _) = box_::gen_keypair();
        let (pk2, _) = box_::gen_keypair();

        let dumb = DumbAuthenticator::new(vec![pk]);

        assert_eq!(dumb.is_valid(&pk), true);
        assert_eq!(dumb.is_valid(&pk2), false);
    }
}
