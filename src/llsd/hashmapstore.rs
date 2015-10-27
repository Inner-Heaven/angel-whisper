use std::sync::{Arc, RwLock};
use std::collections::HashMap;

use sodiumoxide::crypto::box_::PublicKey;

use super::sessionstore::SessionStore;
use super::session::Session;

type Store = Arc<RwLock<HashMap<PublicKey, RwLock<Session>>>>;
pub struct HashMapStore {
   store: Store
}

impl Clone for HashMapStore {
    fn clone(&self) -> HashMapStore {
        HashMapStore {
            store: self.store.clone()
        }
    }
}

/// Very dumb session store. Panics when insert fails.
impl HashMapStore {
    pub fn new() -> HashMapStore {
        HashMapStore {
            store: Arc::new(RwLock::new(HashMap::new()))
        }
    }
}

impl SessionStore for HashMapStore {
    fn insert(&self, session: Session) -> Option<()> {
        // Avoid write locks on map as hard as we can
        if session.is_valid() && !self.store.read().unwrap().contains_key(&session.id()) {
            self.store.write().unwrap().insert(session.id().clone(), RwLock::new(session));
            Some(())
        } else {
            None
        }
    }

    fn find_by_uuid(&self, key: &PublicKey) -> Option<Session> {
        if let Some(lock) = self.store.read().unwrap().get(key) {
            Some(lock.read().unwrap().clone())
        } else {
            None
        }
    }

    fn destroy(&self, session: Session) {
        self.store.write().unwrap().remove(&session.id());
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use super::super::sessionstore::SessionStore;
    use super::super::session::Session;
    use sodiumoxide::crypto::box_;

    fn make_store() -> HashMapStore {
        HashMapStore::new()
    }

    fn key() -> (box_::PublicKey, box_::SecretKey) {
        box_::gen_keypair()
    }
    #[test]
    fn session_not_found() {
        let store = make_store();

        let pair = key();
        assert_eq!(store.find_by_uuid(&pair.0), None)
    }

    #[test]
    fn create_and_read() {
        let store = make_store();
        let session = Session::new(key().0);
        let id = session.id().clone();

        assert_eq!(store.insert(session.clone()), Some(()));
        assert_eq!(store.find_by_uuid(&session.id()), Some(session.clone()));
        assert_eq!(store.find(&id.0), Some(session.clone()));
    }

    #[test]
    fn insert_twice() {
        let store = make_store();
        let session = Session::new(key().0);

        assert_eq!(store.insert(session.clone()), Some(()));
        assert_eq!(store.insert(session.clone()), None);
    }

    #[test]
    fn remove() {
        let store = make_store();
        let session = Session::new(key().0);

        assert_eq!(store.insert(session.clone()), Some(()));
        store.destroy(session.clone());
        assert_eq!(store.find_by_uuid(&session.id()), None);
    }

}
