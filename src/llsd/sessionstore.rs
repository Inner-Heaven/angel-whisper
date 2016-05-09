use sodiumoxide::crypto::box_::PublicKey;
use std::sync::{Arc, RwLock};

pub use super::session::server::Session;
/// This `Trait` defines session storage.
pub trait SessionStore: Clone + Send + Sync {

    /// Look up session by its id
    fn find_by_pk(&self, key: &PublicKey) -> Option<Arc<RwLock<Session>>>;

    /// Shortcut to lookup session from uuid in `&[u8]` representation
    fn find(&self, bytes: &[u8]) -> Option<Arc<RwLock<Session>>> {
        if let Some(_id) = PublicKey::from_slice(bytes) {
            self.find_by_pk(&_id)
        } else {
            None
        }
    }
    /// Try to insert session in to the store. If session already exists in the store — return
    /// None, else return `()`
    fn insert(&self, session: Session) -> Option<()>;
    fn destroy(&self, key: &PublicKey);
}
