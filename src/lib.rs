//! High-level hyper server interfacing with tower-service.
//!
//! ## Features:
//! * `rustls` integration
//! * Graceful shutdown using CancellationToken
//! * Optional connnection middleware
//! * Optional TLS connection middleware, for example for mTLS integration
//!
//! ## Example usage using Axum:
//!
//! ```rust
//! # async fn serve() {
//! let server = tower_server::Builder::new("0.0.0.0:8080".parse().unwrap())
//!     // graceful shutdown setup:
//!     .with_cancellation_token(Default::default())
//!     .bind()
//!     .await
//!     .unwrap();
//!
//! server.serve(axum::Router::new()).await;
//! # }
//! ```
//!
//! ## Example using connection middleware
//!
//! ```rust
//! #[derive(Clone)]
//! struct RemoteAddr(std::net::SocketAddr);
//!
//! # async fn serve() {
//! let server = tower_server::Builder::new("0.0.0.0:8080".parse().unwrap())
//!     .with_connection_middleware(|req, remote_addr| {
//!         req.extensions_mut().insert(RemoteAddr(remote_addr));
//!     })
//!     .bind()
//!     .await
//!     .unwrap();
//!
//! server.serve(axum::Router::new()).await;
//! # }
//! ```
//!
//! ## Example using TLS connection middleware
//!
//! ```rust
//! use rustls_pki_types::CertificateDer;
//! use hyper::body::Incoming;
//!
//! #[derive(Clone)]
//! struct PeerCertMiddleware;
//!
//! /// A request extension that includes the mTLS peer certificate
//! #[derive(Clone)]
//! struct PeerCertificate(CertificateDer<'static>);
//!
//! impl tower_server::tls::TlsConnectionMiddleware for PeerCertMiddleware {
//!     type Data = Option<PeerCertificate>;
//!
//!     /// Step 1: Extract data from the rustls server connection.
//!     /// At this stage of TLS handshake the http::Request doesn't yet exist.
//!     fn data(&self, connection: &rustls::ServerConnection) -> Self::Data {
//!         Some(PeerCertificate(connection.peer_certificates()?.first()?.clone()))
//!     }
//!
//!     /// Step 2: The http::Request now exists, and the request extension can be injected.
//!     fn call(&self, req: &mut http::Request<Incoming>, data: &Option<PeerCertificate>) {
//!         if let Some(peer_certificate) = data {
//!             req.extensions_mut().insert(peer_certificate.clone());
//!         }
//!     }
//! }
//!
//! #[derive(Clone)]
//! struct RemoteAddr(std::net::SocketAddr);
//!
//! # async fn serve() {
//! let server = tower_server::Builder::new("0.0.0.0:8080".parse().unwrap())
//!     .with_tls_connection_middleware(PeerCertMiddleware)
//!     .bind()
//!     .await
//!     .unwrap();
//!
//! server.serve(axum::Router::new()).await;
//! # }
//! ```

use std::net::SocketAddr;
use std::{error::Error as StdError, sync::Arc};

use futures_util::future::poll_fn;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use pin_utils::pin_mut;
use tls::{NoOpTlsConnectionMiddleware, TlsConnectionMiddleware};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{info, trace};

pub mod tls;

/// Server configuration.
#[derive(Clone)]
pub struct Builder<TlsM> {
    addr: SocketAddr,
    scheme: Scheme,
    cancel: CancellationToken,
    connection_middleware: fn(&mut http::Request<Incoming>, SocketAddr),
    tls_connection_middleware: TlsM,
    tls_config_factory: TlsConfigFactory,
}

impl Builder<NoOpTlsConnectionMiddleware> {
    /// Configure using a socket addr using the Http scheme.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            scheme: Scheme::Http,
            cancel: Default::default(),
            connection_middleware: |_, _| {},
            tls_connection_middleware: NoOpTlsConnectionMiddleware,
            tls_config_factory: Arc::new(|| panic!("no TLS server config factory registered")),
        }
    }

    /// Configure the tower server from a server Url with auto-configuration of http scheme.
    #[cfg(feature = "url")]
    pub fn from_url(base_url: url::Url) -> anyhow::Result<Self> {
        use anyhow::anyhow;

        let port = base_url
            .port_or_known_default()
            .ok_or_else(|| anyhow!("server port not deducible from base url"))?;
        let addr: SocketAddr = match base_url.host() {
            // treat domain name as binding on every interface
            Some(url::Host::Domain(_)) => ([0, 0, 0, 0], port).into(),
            Some(url::Host::Ipv4(v4)) => (v4, port).into(),
            Some(url::Host::Ipv6(v6)) => (v6, port).into(),
            None => return Err(anyhow!("no host in url")),
        };

        Ok(Self {
            addr,
            cancel: Default::default(),
            connection_middleware: |_, _| {},
            tls_connection_middleware: NoOpTlsConnectionMiddleware,
            scheme: match base_url.scheme() {
                "http" => Scheme::Http,
                "https" => Scheme::Https,
                scheme => return Err(anyhow!("unknown http server scheme: {scheme}")),
            },
            tls_config_factory: Arc::new(|| panic!("no TLS server config factory registered")),
        })
    }
}

impl<TlsM> Builder<TlsM> {
    /// Set the scheme used by the the server. A Https scheme requires a TLS config factory.
    pub fn with_scheme(mut self, scheme: Scheme) -> Self {
        self.scheme = scheme;
        self
    }

    /// Register a function that acts a connection middleware on any accepted connection.
    /// The middleware is able to modify every incoming request.
    pub fn with_connection_middleware(mut self, middleware: ConnectionMiddleware) -> Self {
        self.connection_middleware = middleware;
        self
    }

    /// Register a TlsConfigFactory, which is a function that gets invoked when TLS is enabled.
    pub fn with_tls_config(mut self, tls: impl Into<TlsConfigFactory>) -> Self {
        self.tls_config_factory = tls.into();
        self
    }

    pub fn with_tls_connection_middleware<T: TlsConnectionMiddleware>(
        self,
        middleware: T,
    ) -> Builder<T> {
        Builder {
            addr: self.addr,
            connection_middleware: self.connection_middleware,
            tls_connection_middleware: middleware,
            scheme: self.scheme,
            cancel: self.cancel,
            tls_config_factory: self.tls_config_factory,
        }
    }

    /// Register a cancellation token that enables graceful shutdown.
    pub fn with_cancellation_token(mut self, cancel: CancellationToken) -> Self {
        self.cancel = cancel;
        self
    }

    /// Build server and bind it to the configured address.
    pub async fn bind(self) -> anyhow::Result<TowerServer<TlsM>> {
        let opt_tls_acceptor = match self.scheme {
            Scheme::Http => None,
            Scheme::Https => Some(TlsAcceptor::from((self.tls_config_factory)())),
        };
        let listener = TcpListener::bind(self.addr).await?;

        Ok(TowerServer {
            listener,
            opt_tls_acceptor,
            cancel: self.cancel,
            connection_middleware: self.connection_middleware,
            tls_connection_middleware: self.tls_connection_middleware,
        })
    }
}

/// Desired HTTP scheme.
#[derive(Clone, Copy)]
pub enum Scheme {
    Http,
    Https,
}

pub type ConnectionMiddleware = fn(&mut http::Request<Incoming>, SocketAddr);

pub type TlsConfigFactory = Arc<dyn Fn() -> Arc<rustls::server::ServerConfig> + Send + Sync>;

/// A bound server, ready for running accept-loop using a tower service.
pub struct TowerServer<TlsM> {
    listener: TcpListener,
    opt_tls_acceptor: Option<TlsAcceptor>,
    cancel: CancellationToken,
    connection_middleware: fn(&mut http::Request<Incoming>, SocketAddr),
    tls_connection_middleware: TlsM,
}

macro_rules! await_connection {
    ($connection:ident, $cancel:ident) => {
        pin_mut!($connection);

        loop {
            tokio::select! {
                biased;
                _ = $connection.as_mut() => {
                    break;
                }
                _ = $cancel.cancelled() => {
                    $connection.as_mut().graceful_shutdown();
                }
            }
        }
    };
}

impl<TlsM> TowerServer<TlsM> {
    /// Access the locally bound address
    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        self.listener.local_addr().map_err(|e| e.into())
    }

    /// Run HTTP accept loop, handling every request using the passwed tower service.
    pub async fn serve<S, B>(self, tower_service: S)
    where
        S: tower_service::Service<
                http::Request<hyper::body::Incoming>,
                Response = http::Response<B>,
            >
            + Send
            + Sync
            + 'static
            + Clone,
        S::Future: 'static + Send,
        S::Error: Into<Box<dyn StdError + Send + Sync + 'static>>,
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn StdError + Send + Sync + 'static>>,
        TlsM: TlsConnectionMiddleware,
    {
        // tracks how long to gracefully await shutdown.
        // Nothing is ever sent on this channel, it's only used for
        // tracking the number of live receivers.
        // each active connection has a clone of `close_rx`,
        // at the end of the function `close_tx.closed()` is awaited,
        // which finishes when no receivers are available.
        let (close_tx, close_rx) = watch::channel(());

        // accept loop
        loop {
            let (tcp_stream, remote_addr) = tokio::select! {
                accept = self.listener.accept() => {
                    match accept {
                        Ok(stream_addr) => stream_addr,
                        Err(_) => {
                            continue;
                        }
                    }
                }
                _ = self.cancel.cancelled() => {
                    trace!("signal received, not accepting new connections");
                    break;
                }
            };

            let opt_tls_acceptor = self.opt_tls_acceptor.clone();
            let close_rx = close_rx.clone();
            let cancel = self.cancel.clone();
            let connection_middleware = self.connection_middleware;
            let tls_connection_middleware = self.tls_connection_middleware.clone();
            let tower_service = tower_service.clone();

            tokio::spawn(async move {
                let connection_builder =
                    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                match opt_tls_acceptor {
                    None => {
                        let connection = connection_builder.serve_connection_with_upgrades(
                            TokioIo::new(tcp_stream),
                            hyper::service::service_fn(move |mut req| {
                                connection_middleware(&mut req, remote_addr);
                                let mut tower_service = tower_service.clone();

                                async move {
                                    poll_fn(|cx| tower_service.poll_ready(cx)).await?;
                                    tower_service.call(req).await
                                }
                            }),
                        );
                        await_connection!(connection, cancel);
                    }
                    Some(tls_acceptor) => {
                        let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                            Ok(tls_stream) => tls_stream,
                            Err(err) => {
                                info!(?err, "failed to perform tls handshake");
                                return;
                            }
                        };

                        let tls_middleware_data =
                            tls_connection_middleware.data(tls_stream.get_ref().1);

                        let connection = connection_builder.serve_connection_with_upgrades(
                            TokioIo::new(tls_stream),
                            hyper::service::service_fn(move |mut req| {
                                connection_middleware(&mut req, remote_addr);
                                tls_connection_middleware.call(&mut req, &tls_middleware_data);
                                let mut tower_service = tower_service.clone();

                                async move {
                                    poll_fn(|cx| tower_service.poll_ready(cx)).await?;
                                    tower_service.call(req).await
                                }
                            }),
                        );
                        await_connection!(connection, cancel);
                    }
                }

                drop(close_rx);
            });
        }

        drop(close_rx);
        trace!(
            "waiting for {} task(s) to finish",
            close_tx.receiver_count()
        );
        close_tx.closed().await;
    }
}
