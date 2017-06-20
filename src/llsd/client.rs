use llsd::frames::Frame;
use llsd::session::client::Session;
use futures::Future;
use std::io;
use std::rc::Rc;
use std::cell::RefCell;

pub trait Engine {

    /// Make a sync RPC call. Default implementation is calling async and wait for it to complete.
    fn make_call(&self, req: Frame) -> Result<Frame, io::Error> {
        self.make_async_call(req).wait()
    }
    /// Make an async RPC call and return Future.
    /// Please note this implies that future must be scheduled to run before it's returned.
    fn make_async_call(&self, req: Frame) -> Box<Future<Item=Frame,Error=io::Error>>;

    /// Return reference to session.
    fn session(&self) -> Rc<RefCell<Session>>;

    /// Helper method to authenticate client with the server. Default implementation uses make_call.
    fn authenticate(&mut self) -> Result<(), io::Error> {
        let session = self.session().clone();

        let hello_frame = session.borrow().make_hello();
        let hello_resp  = try!(self.make_call(hello_frame));
        
        let initiate_frame = session.borrow_mut().make_initiate(&hello_resp).unwrap();
        let initiate_resp = try!(self.make_call(initiate_frame));

        let ready_payload = session.borrow_mut().read_ready(&initiate_resp);
        if let Ok(_is_ready) = ready_payload {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "wat"))
        }
    }
}