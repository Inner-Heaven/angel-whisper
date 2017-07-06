use super::{Handler, ServiceHub};
use byteorder::{BigEndian, ByteOrder};
use bytes::{Bytes, BytesMut};
use errors::{AWError, AWResult};
use llsd::route::Route;
use llsd::session::server::Session;
use std::collections::HashMap;
use std::convert::From;
use std::default::Default;
use std::sync::{Arc, RwLock};

const POISONED_LOCK_MSG: &'static str = "Lock was poisoned";

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

pub trait RouteAction: Send + Sync + 'static {
    fn process(&self,
               route: &Route,
               services: ServiceHub,
               session: Arc<RwLock<Session>>,
               msg: &mut BytesMut)
               -> AWResult<Bytes>;
}
pub struct DynamicRouter {
    store: Arc<RwLock<HashMap<Route, Box<RouteAction>>>>,
}
impl DynamicRouter {
    pub fn register_route<R: Into<Route>, H: RouteAction>(&self, route: R, handler: H) {
        self.store
            .write()
            .expect(POISONED_LOCK_MSG)
            .insert(route.into(), Box::new(handler));
    }
}

impl Default for DynamicRouter {
    fn default() -> DynamicRouter {
        DynamicRouter { store: Arc::new(RwLock::new(HashMap::new())) }
    }
}

impl Router for DynamicRouter {
    fn process(&self,
               route: Route,
               services: ServiceHub,
               session: Arc<RwLock<Session>>,
               msg: &mut BytesMut)
               -> AWResult<Bytes> {
        match self.store.read().expect(POISONED_LOCK_MSG).get(&route) {
            None => Err(AWError::NotImplemented),
            Some(handler) => handler.process(&route, services, session, msg),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use byteorder::{BigEndian, WriteBytesExt};
    use errors::AWResult;
    use llsd::route::Route;
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

    pub struct EchoAction;
    impl Default for EchoAction {
        fn default() -> EchoAction {
            EchoAction {}
        }
    }
    impl RouteAction for EchoAction {
        fn process(&self,
                   _route: &Route,
                   _services: ServiceHub,
                   _session: Arc<RwLock<Session>>,
                   _msg: &mut BytesMut)
                   -> AWResult<Bytes> {
            Ok(b"pong".to_vec().into())
        }
    }

    struct Basic;
    impl Router for Basic {
        fn process(&self,
                   _route: Route,
                   _services: ServiceHub,
                   _session: Arc<RwLock<Session>>,
                   _msg: &mut BytesMut)
                   -> AWResult<Bytes> {
            Ok(b"hello".to_vec().into())
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

        let router = Basic;

        let mut req = Vec::new();
        req.write_u64::<BigEndian>(get_route().id()).unwrap();
        let hello = b"hello".to_vec();
        req.append(&mut hello.clone());

        let res = router.handle(get_hub(), get_session(), &mut req.clone().into());
        assert!(res.is_ok());
        let res_vec = res.unwrap().to_vec();

        assert_eq!(res_vec, hello);
    }

    #[test]
    fn gtfo_router() {
        struct Basic;
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
        req.write_u64::<BigEndian>(get_route().id()).unwrap();
        req.append(&mut b"hello".to_vec());

        let res = router.handle(get_hub(), get_session(), &mut req.into());
        assert!(res.is_ok());
        let res_vec = res.unwrap();

        assert_eq!(res_vec, b"gtfo".to_vec());
    }

    #[test]
    fn malformed() {
        let router = Basic;
        let req = vec![1, 2];

        let res = router.handle(get_hub(), get_session(), &mut req.into());
        assert!(res.is_err());
    }
    #[test]
    fn dynamic_router() {
        let router = DynamicRouter::default();
        router.register_route(get_route(), EchoAction::default());

        let mut req_not_found = Vec::new();
        req_not_found
            .write_u64::<BigEndian>(Route::from("cnn").id())
            .unwrap();
        req_not_found.append(&mut b"hello".to_vec());

        let not_found = router.handle(get_hub(), get_session(), &mut req_not_found.into());
        assert!(not_found.is_err());

        let mut req = Vec::new();
        req.write_u64::<BigEndian>(get_route().id()).unwrap();
        req.append(&mut b"ping".to_vec());

        let pong_res = router.handle(get_hub(), get_session(), &mut req.into());
        assert!(pong_res.is_ok());
        let pong = pong_res.unwrap();
        assert_eq!(pong.as_ref(), b"pong");
    }
}
