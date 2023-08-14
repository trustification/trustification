use std::{
    fmt::Debug,
    io::{self, BufWriter, Write},
    ops::Range,
    path::Path,
    sync::Arc,
};

pub use s3::{creds::Credentials, Region};
use s3::{error::S3Error, Bucket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;
use tantivy::{
    directory::{
        error::{DeleteError, OpenReadError, OpenWriteError},
        FileHandle, OwnedBytes, TerminatingWrite, WatchCallback, WatchHandle, WritePtr,
    },
    Directory, HasLen,
};

use crc32fast::Hasher;

use tantivy::directory::WatchCallbackList;

#[derive(Clone)]
pub struct S3Directory {
    bucket: Bucket,
    watcher: Arc<S3FileWatcher>,
}

impl Debug for S3Directory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Directory")
            .field("bucket", &"foo".to_string())
            .finish()
    }
}

#[derive(Debug)]
pub struct S3File {
    bucket: Bucket,
    path: String,
    data: Vec<u8>,
}

impl S3File {
    fn new(path: &str, bucket: Bucket, data: Vec<u8>) -> Self {
        // log::info!("{}: New s3 file with len {}", path, data.len());
        Self {
            bucket,
            path: path.to_string(),
            data,
        }
    }
}

impl FileHandle for S3File {
    fn read_bytes(&self, range: Range<usize>) -> std::io::Result<OwnedBytes> {
        //        let data = self.bucket.get_object_range_blocking(&self.path, range.start as u64, Some(range.end as u64)).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let data: Vec<u8> = self.data[range].to_vec();
        Ok(OwnedBytes::new(data))
    }
}

impl Write for S3File {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // log::info!("{}: WRITE {} bytes", self.path, buf.len());
        self.data.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // log::info!("{}: FLUSH {} bytes", self.path, self.data.len());
        Ok(())
    }
}

impl TerminatingWrite for S3File {
    fn terminate_ref(&mut self, _: tantivy::directory::AntiCallToken) -> io::Result<()> {
        // log::info!("{}: TERMINATE REF, size is {}", self.path, self.data.len());
        match self.bucket.put_object_blocking(&self.path, &self.data[..]) {
            Ok(_) => Ok(()),
            Err(e) => {
                panic!("{:?}", e);
            }
        }
    }
}

impl HasLen for S3File {
    fn len(&self) -> usize {
        self.data.len()
    }
}

/*
impl core::ops::Deref for S3File {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        todo!()
    }

}*/

fn s3_to_io(e: S3Error) -> Arc<io::Error> {
    Arc::new(io::Error::new(io::ErrorKind::Other, e))
}

impl S3Directory {
    pub fn new(bucket: Bucket) -> Self {
        let root_path = Path::new(INDEX_PATH);
        Self {
            bucket: bucket.clone(),
            watcher: Arc::new(S3FileWatcher::new(bucket, &root_path.join("meta.json"))),
        }
    }
}

const INDEX_PATH: &str = "/index/";
impl Directory for S3Directory {
    fn get_file_handle(&self, path: &Path) -> Result<Arc<dyn FileHandle>, OpenReadError> {
        if let Some(p) = path.to_str() {
            let p = format!("{}{}", INDEX_PATH, p);
            // log::info!("{}: Get file handle", p);
            let p2 = p.clone();
            let pb = path.to_path_buf();
            let bucket = self.bucket.clone();
            let result = bucket.get_object_blocking(&p).map_err(|e| {
                // log::info!("GET FILE HANDLE ERROR: {:?}", e);
                OpenReadError::IoError {
                    io_error: s3_to_io(e),
                    filepath: pb,
                }
            })?;
            Ok(Arc::new(S3File::new(&p2, self.bucket.clone(), result.to_vec())))
        } else {
            // log::info!("ARROR MAKING STR OF PATH {:?}", path);

            Err(OpenReadError::FileDoesNotExist(path.to_path_buf()))
        }
    }

    fn delete(&self, path: &Path) -> Result<(), DeleteError> {
        if let Some(p) = path.to_str() {
            let p = format!("{}{}", INDEX_PATH, p);
            // log::info!("DELETE {}", p);
            self.bucket.delete_object_blocking(p).map_err(|e| {
                // log::info!("DELETE IO ERROR :{:?}", e);
                DeleteError::IoError {
                    io_error: s3_to_io(e),
                    filepath: path.to_path_buf(),
                }
            })?;
            Ok(())
        } else {
            Err(DeleteError::FileDoesNotExist(path.to_path_buf()))
        }
    }

    fn exists(&self, path: &Path) -> Result<bool, OpenReadError> {
        if let Some(p) = path.to_str() {
            let p = format!("{}{}", INDEX_PATH, p);
            // log::info!("{}: check exists", p);
            let bucket = self.bucket.clone();
            let result = bucket.head_object_blocking(p);

            match result {
                Err(S3Error::HttpFailWithBody(status, _)) if status == 404 => Ok(false),
                Err(e) => {
                    // log::info!("EXISTS ERROR: {:?}", e);
                    Err(OpenReadError::IoError {
                        io_error: s3_to_io(e),
                        filepath: path.to_path_buf(),
                    })
                }
                Ok(_) => Ok(true),
            }
        } else {
            // log::info!("ARROR MAKING STR OF PATH {:?}", path);
            Err(OpenReadError::FileDoesNotExist(path.to_path_buf()))
        }
    }

    fn open_write(&self, path: &Path) -> Result<WritePtr, OpenWriteError> {
        if let Some(p) = path.to_str() {
            let p = format!("{}{}", INDEX_PATH, p);
            // log::info!("{}: open write", p);
            let bucket = self.bucket.clone();
            let result = bucket.get_object_blocking(&p);

            if let Err(S3Error::HttpFailWithBody(404, _)) = result {
                Ok(BufWriter::new(Box::new(S3File::new(
                    &p,
                    self.bucket.clone(),
                    Vec::new(),
                ))))
            } else {
                Err(OpenWriteError::FileAlreadyExists(path.to_path_buf()))
            }
        } else {
            // log::info!("OPEN WRITE IO ERROR");
            Err(OpenWriteError::IoError {
                io_error: Arc::new(io::Error::new(io::ErrorKind::Other, "".to_string())),
                filepath: path.to_path_buf(),
            })
        }
    }

    fn atomic_read(&self, path: &Path) -> Result<Vec<u8>, OpenReadError> {
        if let Some(p) = path.to_str() {
            let p = format!("{}{}", INDEX_PATH, p);
            // log::info!("{}: atomic read", p);
            let bucket = self.bucket.clone();
            let result = bucket.get_object_blocking(p);

            match result {
                Err(S3Error::HttpFailWithBody(status, _)) if status == 404 => {
                    Err(OpenReadError::FileDoesNotExist(path.to_path_buf()))
                }
                Err(e) => {
                    // log::info!("aTOMIC READ ERROR: {:?}", e);
                    Err(OpenReadError::IoError {
                        io_error: s3_to_io(e),
                        filepath: path.to_path_buf(),
                    })
                }
                Ok(data) => Ok(data.to_vec()),
            }
        } else {
            // log::info!("ARROR MAKING STR OF PATH {:?}", path);
            Err(OpenReadError::FileDoesNotExist(path.to_path_buf()))
        }
    }

    fn atomic_write(&self, path: &Path, data: &[u8]) -> std::io::Result<()> {
        if let Some(p) = path.to_str() {
            let p = format!("{}{}", INDEX_PATH, p);
            // log::info!("{}: atomic write", p);
            let bucket = self.bucket.clone();
            let data = data.to_vec();
            let result = bucket.put_object_blocking(p, &data);

            match result {
                Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
                Ok(_) => Ok(()),
            }
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "".to_string()))
        }
    }

    fn sync_directory(&self) -> std::io::Result<()> {
        Ok(())
    }

    /// Registers a callback that will be called whenever a change on the `meta.json`
    /// using the [`Directory::atomic_write()`] API is detected.
    ///
    /// The behavior when using `.watch()` on a file using [`Directory::open_write()`] is, on the
    /// other hand, undefined.
    ///
    /// The file will be watched for the lifetime of the returned `WatchHandle`. The caller is
    /// required to keep it.
    /// It does not override previous callbacks. When the file is modified, all callback that are
    /// registered (and whose [`WatchHandle`] is still alive) are triggered.
    ///
    /// Internally, tantivy only uses this API to detect new commits to implement the
    /// `OnCommit` `ReloadPolicy`. Not implementing watch in a `Directory` only prevents the
    /// `OnCommit` `ReloadPolicy` to work properly.
    fn watch(&self, watch_callback: WatchCallback) -> tantivy::Result<WatchHandle> {
        Ok(self.watcher.watch(watch_callback))
    }
}

const POLLING_INTERVAL: Duration = Duration::from_millis(if cfg!(test) { 1 } else { 500 });

pub struct S3FileWatcher {
    bucket: Bucket,
    path: Arc<Path>,
    callbacks: Arc<WatchCallbackList>,
    state: Arc<AtomicUsize>, // 0: new, 1: runnable, 2: terminated
}

impl S3FileWatcher {
    pub fn new(bucket: Bucket, path: &Path) -> S3FileWatcher {
        S3FileWatcher {
            bucket,
            path: Arc::from(path),
            callbacks: Default::default(),
            state: Default::default(),
        }
    }

    pub fn spawn(&self) {
        if self
            .state
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        let path = self.path.clone();
        let callbacks = self.callbacks.clone();
        let state = self.state.clone();

        let bucket = self.bucket.clone();
        thread::Builder::new()
            .name("index-s3-meta-file-watcher".to_string())
            .spawn(move || {
                let mut current_checksum_opt = None;

                while state.load(Ordering::SeqCst) == 1 {
                    if let Ok(checksum) = Self::compute_checksum(&bucket, &path) {
                        let metafile_has_changed = current_checksum_opt
                            .map(|current_checksum| current_checksum != checksum)
                            .unwrap_or(true);
                        if metafile_has_changed {
                            log::info!("Meta file {:?} was modified", path);
                            current_checksum_opt = Some(checksum);
                            // We actually ignore callbacks failing here.
                            // We just wait for the end of their execution.
                            let _ = callbacks.broadcast().wait();
                        }
                    }

                    thread::sleep(POLLING_INTERVAL);
                }
            })
            .expect("Failed to spawn meta s3 file watcher thread");
    }

    pub fn watch(&self, callback: WatchCallback) -> WatchHandle {
        let handle = self.callbacks.subscribe(callback);
        self.spawn();
        handle
    }

    fn compute_checksum(bucket: &Bucket, path: &Path) -> Result<u32, io::Error> {
        match bucket.get_object_blocking(path.to_str().unwrap()) {
            Ok(response) => {
                let data = response.to_vec();

                let mut hasher = Hasher::new();
                hasher.update(&data[..]);
                Ok(hasher.finalize())
            }
            Err(e) => {
                // log::warn!("Failed to open meta file {:?}: {:?}", path, e);
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }
}

impl Drop for S3FileWatcher {
    fn drop(&mut self) {
        self.state.store(2, Ordering::SeqCst);
    }
}
