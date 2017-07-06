use super::{Handler, ServiceHub};
use byteorder::{BigEndian, ByteOrder};

use bytes::{Bytes, BytesMut};
use errors::{AWError, AWResult};
use llsd::session::server::Session;
use murmurhash64::murmur_hash64a as hash;
use std::convert::From;
use std::sync::{Arc, RwLock};

const SEED: u64 = 69;

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Route(u64);

impl From<u64> for Route {
    #[inline]
    fn from(src: u64) -> Route {
        Route(src)
    }
}
impl From<&'static str> for Route {
    #[inline]
    fn from(src: &'static str) -> Route {
        Route(hash(src.as_bytes(), SEED))
    }
}
impl From<String> for Route {
    #[inline]
    fn from(src: String) -> Route {
        Route(hash(src.as_bytes(), SEED))
    }
}

pub trait Router: Send + Sync + 'static {
    fn route_from_payload(&self, payload: &mut BytesMut) -> AWResult<Route> {
        if payload.len() < 8 {
            return Err(AWError::InvalidRoute);
        }
        let route = payload.split_to(8);
        let hash = BigEndian::read_u64(&route);
        Ok(Route::from(hash))
    }
    fn process(&self,
               route: Route,
               services: ServiceHub,
               session: Arc<RwLock<Session>>,
               msg: &mut BytesMut)
               -> AWResult<Bytes>;
}
impl<R> Handler for R
where
    R: Router,
{
    fn handle(&self,
              services: ServiceHub,
              session: Arc<RwLock<Session>>,
              msg: &mut BytesMut)
              -> AWResult<Bytes> {
        let route = self.route_from_payload(msg)?;
        self.process(route, services, session, msg)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use byteorder::{BigEndian, WriteBytesExt};
    use errors::AWResult;
    use llsd::session::server::Session;


    use std::sync::{Arc, RwLock};
    use system::{Handler, ServiceHub};

    use typemap::TypeMap;

    fn get_route() -> Route {
        Route::from("system::test")
    }

    fn get_hub() -> ServiceHub {
        Arc::new(RwLock::new(TypeMap::custom()))
    }

    fn get_session() -> Arc<RwLock<Session>> {
        Arc::new(RwLock::new(Session::default()))
    }

    struct Basic {}
    impl Router for Basic {
        fn process(&self,
                   route: Route,
                   _services: ServiceHub,
                   _session: Arc<RwLock<Session>>,
                   _msg: &mut BytesMut)
                   -> AWResult<Bytes> {
            if route == get_route() {
                Ok(b"hello".to_vec().into())
            } else {
                unimplemented!()
            }
        }
    }

    struct GtfoHandler;
    impl Handler for GtfoHandler {
        fn handle(&self,
                  _: ServiceHub,
                  _: Arc<RwLock<Session>>,
                  _: &mut BytesMut)
                  -> AWResult<Bytes> {
            Ok(Bytes::from(b"gtfo".to_vec()))
        }
    }


    #[test]
    fn echo_router() {

        let router = Basic {};

        let mut req = Vec::new();
        req.write_u64::<BigEndian>(get_route().0).unwrap();
        let hello = b"hello".to_vec();
        req.append(&mut hello.clone());

        let res = router.handle(get_hub(), get_session(), &mut req.clone().into());
        assert!(res.is_ok());
        let res_vec = res.unwrap().to_vec();

        assert_eq!(res_vec, hello);
    }

    #[test]
    fn gtfo_router() {
        struct Basic {};
        impl Router for Basic {
            fn process(&self,
                       _route: Route,
                       services: ServiceHub,
                       session: Arc<RwLock<Session>>,
                       msg: &mut BytesMut)
                       -> AWResult<Bytes> {
                let handler = GtfoHandler;
                handler.handle(services, session, msg)
            }
        }
        let router = Basic {};

        let mut req = Vec::new();
        req.write_u64::<BigEndian>(get_route().0).unwrap();
        req.append(&mut b"hello".to_vec());

        let res = router.handle(get_hub(), get_session(), &mut req.into());
        assert!(res.is_ok());
        let res_vec = res.unwrap();

        assert_eq!(res_vec, b"gtfo".to_vec());
    }

    #[test]
    fn malformed() {
        let router = Basic {};
        let req = vec![1, 2];

        let res = router.handle(get_hub(), get_session(), &mut req.into());
        assert!(res.is_err());
    }
}
