//! TLS support.

use std::sync::Arc;

use futures_util::{stream::BoxStream, StreamExt};
use http::Request;
use hyper::body::Incoming;
use rustls::{ServerConfig, ServerConnection};

/// A TLS configurer that may change during lifetime of a server.
///
/// The configurer supports "hotpatching" a running server with new configuration.
pub trait TlsConfigurer {
    /// Whether the configuration may change over time.
    fn is_dynamic(&self) -> bool;

    /// Turn the configurer into a stream of TLS [ServerConfig]s.
    fn into_stream(self) -> BoxStream<'static, Arc<ServerConfig>>;
}

impl TlsConfigurer for () {
    fn is_dynamic(&self) -> bool {
        false
    }

    fn into_stream(self) -> BoxStream<'static, Arc<ServerConfig>> {
        futures_util::stream::empty().boxed()
    }
}

impl TlsConfigurer for rustls::server::ServerConfig {
    fn is_dynamic(&self) -> bool {
        false
    }

    fn into_stream(self) -> BoxStream<'static, Arc<ServerConfig>> {
        futures_util::stream::iter([Arc::new(self)]).boxed()
    }
}

impl TlsConfigurer for Arc<rustls::server::ServerConfig> {
    fn is_dynamic(&self) -> bool {
        false
    }

    fn into_stream(self) -> BoxStream<'static, Arc<ServerConfig>> {
        futures_util::stream::iter([self]).boxed()
    }
}

impl TlsConfigurer for Arc<dyn Fn() -> Arc<rustls::server::ServerConfig> + Send + Sync> {
    fn is_dynamic(&self) -> bool {
        false
    }

    fn into_stream(self) -> BoxStream<'static, Arc<ServerConfig>> {
        futures_util::stream::once(async move { (self)() }).boxed()
    }
}

impl TlsConfigurer for BoxStream<'static, Arc<ServerConfig>> {
    fn is_dynamic(&self) -> bool {
        true
    }

    fn into_stream(self) -> BoxStream<'static, Arc<ServerConfig>> {
        self
    }
}

/// A middleware for Tls connections.
///
/// This middleware is implemented in two steps, first a data extraction step taking a [ServerConnection],
/// then a HTTP request middleware runs with that data as a parameter.
pub trait TlsConnectionMiddleware: Clone + Send + 'static {
    /// The data extracted from the rustls ServerConnection.
    type Data: Send;

    /// Extract data from a [ServerConnection].
    fn data(&self, connection: &ServerConnection) -> Self::Data;

    /// Call middleware with extracted data.
    fn call(&self, req: &mut Request<Incoming>, data: &Self::Data);
}

/// A TLS connection middleware that does nothing.
#[derive(Clone, Copy)]
pub struct NoOpTlsConnectionMiddleware;

impl TlsConnectionMiddleware for NoOpTlsConnectionMiddleware {
    type Data = ();

    fn data(&self, _connection: &ServerConnection) -> Self::Data {}

    fn call(&self, _req: &mut Request<Incoming>, _data: &Self::Data) {}
}
