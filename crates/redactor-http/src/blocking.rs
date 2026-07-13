use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub(crate) struct BlockingExecutor {
    permits: Arc<Semaphore>,
}

impl Default for BlockingExecutor {
    fn default() -> Self {
        let parallelism = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1);
        Self {
            permits: Arc::new(Semaphore::new(parallelism)),
        }
    }
}

impl BlockingExecutor {
    pub(crate) async fn run<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .context("blocking executor closed")?;
        tokio::task::spawn_blocking(move || run_with_permit(permit, operation))
            .await
            .context("blocking operation failed to join")?
    }
}

fn run_with_permit<T>(
    _permit: OwnedSemaphorePermit,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    operation()
}
