use sodiumoxide::crypto::box_::PublicKey;

pub use super::session::Session;

/// This `Trait` defines session storage.
pub trait SessionStore: Clone + Send + Sync {

    /// Look up session by its id
    fn find_by_uuid(&self, key: &PublicKey) -> Option<Session>;

    /// Shortcut to lookup session from uuid in `&[u8]` representation
    fn find(&self, bytes: &[u8]) -> Option<Session> {
        if let Some(_id) = PublicKey::from_slice(bytes) {
            self.find_by_uuid(&_id)
        } else {
            None
        }
    }

    fn insert(&self, session: Session) -> Option<()>;
    fn destroy(&self, session: Session);

}
