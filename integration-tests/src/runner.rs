use super::*;
use std::thread::JoinHandle;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;

pub struct Runner {
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<anyhow::Result<()>>>,
}

impl Runner {
    pub fn spawn<F, Fut>(f: F) -> Self
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<()>>,
    {
        let (tx, rx) = oneshot::channel::<()>();

        // spawn the application

        let handle = std::thread::spawn(|| {
            let runtime = Runtime::new().unwrap();
            runtime.block_on(async {
                let f = f();
                select! {
                    result = f => {
                        result
                    },
                    _ = rx => {
                        Ok(())
                    },
                }
            })
        });

        Self {
            shutdown: Some(tx),
            handle: Some(handle),
        }
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            shutdown.send(()).unwrap();
        }
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap().unwrap();
        }
    }
}
