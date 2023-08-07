use std::{fmt::Debug, ops::{DerefMut, Range}, path::{Path, PathBuf}, sync::Arc, io::{self, BufWriter, Write}};

use s3::{creds::error::CredentialsError, error::S3Error, Bucket};
pub use s3::{creds::Credentials, Region};
use tantivy::{Directory, directory::{DirectoryClone, FileHandle, OwnedBytes, error::{OpenReadError, DeleteError, OpenWriteError}, WritePtr, WatchHandle, WatchCallback, TerminatingWrite}, HasLen};
use async_trait::async_trait;

#[derive(Clone)]
pub struct S3Directory {
    bucket: Bucket,
}

impl Debug for S3Directory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Directory").field("bucket", &"foo".to_string()).finish()
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
        Self {
            bucket,
            path: path.to_string(),
            data,
        }
    }
}

impl FileHandle for S3File {
    fn read_bytes(&self, range: Range<usize>) -> std::io::Result<OwnedBytes>  {
        let data = self.bucket.get_object_range_blocking(&self.path, range.start as u64, Some(range.end as u64)).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let data: Vec<u8> = data.to_vec();
        Ok(OwnedBytes::new(data))
    }
}

impl Write for S3File {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        log::info!("{}: WRITE {} bytes", self.path, buf.len());
        self.data.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        log::info!("{}: FLUSH {} bytes", self.path, self.data.len());
        Ok(())
    }
}

impl TerminatingWrite for S3File {
    fn terminate_ref(&mut self, _: tantivy::directory::AntiCallToken) -> io::Result<()> {
        log::info!("{}: TERMINATE REF", self.path);
        match self.bucket.put_object_blocking(&self.path, &self.data[..]) {
            Ok(_) => {
                Ok(())
            }
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
        Self {
            bucket
        }
    }
}


const INDEX_PATH: &'static str = "/index/";
impl Directory for S3Directory {
    fn get_file_handle(&self, path: &Path) -> Result<Arc<dyn FileHandle>, OpenReadError> {
        if let Some(p) = path.to_str() {
            let p = format!("{}{}", INDEX_PATH, p);
            log::info!("{}: Get file handle", p);
            let p2 = p.clone();
            let pb = path.to_path_buf();
            let bucket = self.bucket.clone();
            let result = bucket.get_object_blocking(&p).map_err(|e| OpenReadError::IoError { io_error: s3_to_io(e), filepath: pb })?;
            Ok(Arc::new(S3File::new(&p2, self.bucket.clone(), result.to_vec())))
        } else {
            Err(OpenReadError::FileDoesNotExist(path.to_path_buf()))
        }
    }

    fn delete(&self, path: &Path) -> Result<(), DeleteError> {
        if let Some(p) = path.to_str() {
            let p = format!("{}{}", INDEX_PATH, p);
            log::info!("DELETE {}", p);
            self.bucket.delete_object_blocking(p).map_err(|e| DeleteError::IoError { io_error: s3_to_io(e), filepath: path.to_path_buf() })?;
            Ok(())
        } else {
            Err(DeleteError::FileDoesNotExist(path.to_path_buf()))
        }
    }

    fn exists(&self, path: &Path) -> Result<bool, OpenReadError> {
        if let Some(p) = path.to_str() {
            let p = format!("{}{}", INDEX_PATH, p);
            log::info!("{}: exists", p);
            let bucket = self.bucket.clone();
            let result = bucket.head_object_blocking(&p);

            match result {
                Err(S3Error::HttpFailWithBody(status, _, )) if status == 404 => {
                    Ok(false)
                }
                Err(e) => {
                    return Err(OpenReadError::IoError { io_error: s3_to_io(e), filepath: path.to_path_buf() });
                }
                Ok(_) => {
                    Ok(true)
                }
            }
        } else {
            Err(OpenReadError::FileDoesNotExist(path.to_path_buf()))
        }
    }

    fn open_write(&self, path: &Path) -> Result<WritePtr, OpenWriteError> {
        if let Some(p) = path.to_str() {
            let p = format!("{}{}", INDEX_PATH, p);
            log::info!("{}: open write", p);
            let bucket = self.bucket.clone();
            let result = bucket.get_object_blocking(&p);

            if let Err(S3Error::HttpFailWithBody(404, _)) = result {
                Ok(BufWriter::new(Box::new(S3File::new(&p, self.bucket.clone(), Vec::new()))))
            } else {
                Err(OpenWriteError::FileAlreadyExists(path.to_path_buf()))
            }
        } else {
            Err(OpenWriteError::IoError { io_error: Arc::new(io::Error::new(io::ErrorKind::Other, "".to_string())), filepath: path.to_path_buf() })
        }

    }

    fn atomic_read(&self, path: &Path) -> Result<Vec<u8>, OpenReadError> {
        if let Some(p) = path.to_str() {
            let p = format!("{}{}", INDEX_PATH, p);
            log::info!("{}: atomic read", p);
            let bucket = self.bucket.clone();
            let result = bucket.get_object_blocking(&p);

            match result {
                Err(S3Error::HttpFailWithBody(status, _, )) if status == 404 => {
                    Err(OpenReadError::FileDoesNotExist(path.to_path_buf()))
                }
                Err(e) => {
                    Err(OpenReadError::IoError { io_error: s3_to_io(e), filepath: path.to_path_buf() })
                }
                Ok(data) => {
                    Ok(data.to_vec())
                }
            }
        } else {
            Err(OpenReadError::FileDoesNotExist(path.to_path_buf()))
        }
    }

    fn atomic_write(&self, path: &Path, data: &[u8]) -> std::io::Result<()> {
        if let Some(p) = path.to_str() {
            let p = format!("{}{}", INDEX_PATH, p);
            log::info!("{}: atomic write", p);
            let bucket = self.bucket.clone();
            let data = data.to_vec();
            let result = bucket.put_object_blocking(&p, &data);

            match result {
                Err(e) => {
                    Err(io::Error::new(io::ErrorKind::Other, e))
                }
                Ok(_) => {
                    Ok(())
                }
            }
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "".to_string()))
        }
    }

    fn sync_directory(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn watch(&self, watch_callback: WatchCallback) -> tantivy::Result<WatchHandle> {
        todo!()
    }
}
