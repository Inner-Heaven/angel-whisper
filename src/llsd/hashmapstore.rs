use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use std::default::Default;

use sodiumoxide::crypto::box_::PublicKey;

use super::sessionstore::SessionStore;
use super::session::server::Session;
use super::session::Sendable;

const POISONED_LOCK_MSG: &'static str = "Lock was poisoned";

type Store = Arc<RwLock<HashMap<PublicKey, Arc<RwLock<Session>>>>>;
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

impl SessionStore for HashMapStore {
    fn insert(&self, session: Session) -> Option<()> {
        // Avoid write locks on map as hard as we can
        if session.is_valid() && !self.store.read().expect(POISONED_LOCK_MSG).contains_key(&session.id()) {
            self.store.write().expect(POISONED_LOCK_MSG).insert(session.id(), Arc::new(RwLock::new(session)));
            Some(())
        } else {
            None
        }
    }

    fn find_by_pk(&self, key: &PublicKey) -> Option<Arc<RwLock<Session>>> {
        if let Some(lock) = self.store.read().expect(POISONED_LOCK_MSG).get(key) {
            Some(lock.clone())
        } else {
            None
        }
    }

    fn destroy(&self, key: &PublicKey) {
        self.store.write().expect(POISONED_LOCK_MSG).remove(key);
    }
}

impl Default for HashMapStore {
    fn default() -> HashMapStore {
        HashMapStore {
            store: Arc::new(RwLock::new(HashMap::new()))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use super::super::sessionstore::SessionStore;
    use super::super::session::server::Session;
    use super::super::session::Sendable;
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
        assert!(store.find_by_pk(&pair.0).is_none())
    }

    #[test]
    fn create_and_read() {
        let store = make_store();
        let session = Session::new(key().0);
        let id = session.id().clone();

        assert_eq!(store.insert(session.clone()), Some(()));
        let subject1 = store.find_by_pk(&id).unwrap();
        let subj1_guard = subject1.read().unwrap();
        assert_eq!(*subj1_guard, session);
        let subject2 =  store.find(&id.0).unwrap();
        let subj2_guard = subject2.read().unwrap();
        assert_eq!(subj2_guard.id(), session.id());
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
        store.destroy(&session.id());
        let subject = store.find_by_pk(&session.id());
        assert!(subject.is_none());
    }

}
