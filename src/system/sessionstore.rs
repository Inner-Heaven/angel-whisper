

pub use llsd::session::server::Session;
use sodiumoxide::crypto::box_::PublicKey;
use std::sync::{Arc, RwLock};
/// This `Trait` defines session storage.
pub trait SessionStore: Clone + Send + Sync {
    /// Look up session by its id
    fn find_by_pk(&self, key: &PublicKey) -> Option<Arc<RwLock<Session>>>;

    /// Shortcut to lookup session from uuid in `&[u8]` representation
    fn find(&self, bytes: &[u8]) -> Option<Arc<RwLock<Session>>> {
        let key = PublicKey::from_slice(bytes).expect("Malformed bytes were passed as PublicKey");
        self.find_by_pk(&key)
    }
    /// Try to insert session in to the store. If session already exists in the
    /// store — return
    /// None, else return `()`
    fn insert(&self, session: Session) -> Option<()>;
    fn destroy(&self, key: &PublicKey);
}
