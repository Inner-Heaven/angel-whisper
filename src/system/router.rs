use std::convert::{From, Into};
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use std::default::Default;

use murmurhash64::murmur_hash64a as hash;
use byteorder::{BigEndian, ByteOrder};

use super::{Handler, ServiceHub};
use ::errors::{AWResult,AWErrorKind};
use ::llsd::session::server::Session;

const SEED: u64 = 69;
const POISONED_LOCK_MSG: &'static str = "Lock was poisoned";

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Route(u64);

impl From<u64> for Route {
    fn from(src: u64) -> Route {
        Route(src)
    }
}
impl From<&'static str> for Route {
    fn from(src: &'static str) -> Route {
        Route(hash(src.as_bytes(), SEED))
    }
}
impl From<String> for Route {
    fn from(src: String) -> Route {
        Route(hash(src.as_bytes(), SEED))
    }
}


#[derive(Clone)]
pub struct Router {
    store: Arc<RwLock<HashMap<Route, Box<Handler>>>>
}

impl Router {
    pub fn register_route<R: Into<Route>, H: Handler>(&self, route: R, handler: H) {
        self.store.write().expect(POISONED_LOCK_MSG).insert(route.into(), Box::new(handler));
    }
}
impl Default for Router {
    fn default() -> Router {
        Router {
            store: Arc::new(RwLock::new(HashMap::new()))
        }
    }
}

impl Handler for Router {
    fn handle(&self, services: ServiceHub, session: Arc<RwLock<Session>>, msg: Vec<u8>) -> AWResult<Vec<u8>> {
         if msg.len() < 8 {
            fail!(AWErrorKind::BadFrame);
        }
        let route = BigEndian::read_u64(&msg);
        match self.store.read().expect(POISONED_LOCK_MSG).get(&route.into()) {
            None    => fail!(AWErrorKind::BadFrame),
            Some(handler)   => handler.handle(services, session, msg)
        }
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use ::llsd::session::server::Session;
    use system::{Handler, ServiceHub};
    use errors::AWResult;


    use std::sync::{Arc, RwLock};

    use typemap::TypeMap;
    use byteorder::{WriteBytesExt, BigEndian};

    fn get_route() -> Route {
        Route::from("system::test")
    }

    fn get_hub() -> ServiceHub {
        Arc::new(RwLock::new(TypeMap::new()))
    }
    fn echo(_: ServiceHub, _: Arc<RwLock<Session>>, msg: Vec<u8>) -> AWResult<Vec<u8>> {
        Ok(msg)
    }

    fn get_session() -> Arc<RwLock<Session>> {
        Arc::new(RwLock::new(Session::default()))
    }


    struct GtfoHandler;
    impl Handler for GtfoHandler {
        fn handle(&self, _: ServiceHub, _: Arc<RwLock<Session>>, _: Vec<u8>) -> AWResult<Vec<u8>> {
            Ok(b"gtfo".to_vec())
        }
    }
    #[test]
    fn echo_router() {
        let router = Router::default();
        router.register_route(get_route(), echo);

        let mut req = Vec::new();
        req.write_u64::<BigEndian>(get_route().0).unwrap();
        req.append(&mut b"hello".to_vec());

        let res = router.handle(get_hub(), get_session(), req.clone());
        assert!(res.is_ok());
        let res_vec = res.unwrap();

        assert_eq!(res_vec, req);
    }

    #[test]
    fn gtfo_router() {
        let router = Router::default();
        router.register_route(get_route(), GtfoHandler);
        let mut req = Vec::new();
        req.write_u64::<BigEndian>(get_route().0).unwrap();
        req.append(&mut b"hello".to_vec());

        let res = router.handle(get_hub(), get_session(), req.clone());
        assert!(res.is_ok());
        let res_vec = res.unwrap();

        assert_eq!(res_vec, b"gtfo".to_vec());
    }

    #[test]
    fn not_found() {
        let router = Router::default();
        let mut req = Vec::new();
        req.write_u64::<BigEndian>(get_route().0).unwrap();
        req.append(&mut b"hello".to_vec());

        let res = router.handle(get_hub(), get_session(), req.clone());
        assert!(res.is_err());
    }

    #[test]
    fn malformed() {
        let router = Router::default();
        let req = vec![1,2];

        let res = router.handle(get_hub(), get_session(), req.clone());
        assert!(res.is_err());
    }
}
