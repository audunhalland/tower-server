# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [0.3.1] - 2025-02-07
### Fixed
- Graceful shutdown 100% CPU usage bug (a loop was the wrong construct).

## [0.3.0] - 2025-01-19
### Changed
- Introduce `TlsConfigurer` trait for TLS configuration. Replaces `TlsConfigFactory`.
- Renamed `with_cancellation_token` to `with_graceful_shutdown`.
- Turned off default-features of `rustls` and `tokio-rustls`.

### Added
- Support for TLS configuration rotation based on streaming.

## [0.2.3] - 2025-01-19
### Added
- `doc_auto_cfg` on docs.rs

## [0.2.2] - 2025-01-17
### Added
- Shutdown signal shorthand.

## [0.2.1] - 2025-01-03
### Fixed
- Set default generic parameter for Builder.

## [0.2.0] - 2025-01-03
### Changed
- Completely changed builder API for working with TLS connection middleware.
