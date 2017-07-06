use murmurhash64::murmur_hash64a as hash;
use std::convert::From;

const SEED: u64 = 69;

/// Service that have multiple handlers should use this for addressing. It takes string, hash it with murmur64 and use result (u64) for addressing.
#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Route(u64);
impl Route {
    /// Return u64 representation of route
    pub fn id(&self) -> u64 {
        self.0
    }
}

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