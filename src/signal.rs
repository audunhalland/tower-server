//! Signal support.

use tokio_util::sync::CancellationToken;

/// Spawn a tokio signal listener that listens to `terminate` and `ctrl_c`.
///
/// Returns a [CancellationToken] that can be used with [crate::Builder].
pub fn termination_signal() -> CancellationToken {
    let cancel = CancellationToken::new();
    tokio::spawn({
        let cancel = cancel.clone();
        async move {
            let terminate = async {
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to install signal handler")
                    .recv()
                    .await;
            };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    cancel.cancel();
                }
                _ = terminate => {
                    cancel.cancel();
                }
            }
        }
    });

    cancel
}
