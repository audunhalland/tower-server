use http::Request;
use hyper::body::Incoming;
use rustls::ServerConnection;

/// A middleware for Tls connections.
///
/// This middleware is implemented in two steps, first a data extraction step taking a [ServerConnection],
/// then a HTTP request middleware runs with that data as a parameter.
pub trait TlsConnectionMiddleware: Clone + Send + 'static {
    type Data: Send;

    /// Extract data from a [ServerConnection].
    fn data(&self, connection: &ServerConnection) -> Self::Data;

    /// Call middleware with extracted data.
    fn call(&self, req: &mut Request<Incoming>, data: &Self::Data);
}

#[derive(Clone, Copy)]
pub(crate) struct NoopTlsConnectionMiddleware;

impl TlsConnectionMiddleware for NoopTlsConnectionMiddleware {
    type Data = ();

    fn data(&self, _connection: &ServerConnection) -> Self::Data {}

    fn call(&self, _req: &mut Request<Incoming>, _data: &Self::Data) {}
}
