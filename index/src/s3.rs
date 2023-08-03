use std::{fmt::Debug, ops::{DerefMut, Range}, path::{Path, PathBuf}, sync::Arc};

use s3::{creds::error::CredentialsError, error::S3Error, Bucket};
pub use s3::{creds::Credentials, Region};
use tantivy::{Directory, directory::{DirectoryClone, FileHandle, OwnedBytes, error::{OpenReadError, DeleteError, OpenWriteError}, WritePtr, WatchHandle, WatchCallback}};

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
    path: PathBuf,
}

impl FileHandle for S3File {
    #[doc = " Reads a slice of bytes."]
#[doc = ""]
#[doc = " This method may panic if the range requested is invalid."]
    fn read_bytes(&self, range: Range<usize>) -> std::io::Result<OwnedBytes>  {
        todo!()
    }
}

impl core::ops::Deref for S3File {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        todo!()
    }

}

impl Directory for S3Directory {
    fn get_file_handle(&self, path: &Path) -> Result<Arc<dyn FileHandle>, OpenReadError> {
        todo!()
    }

    fn delete(&self, path: &Path) -> Result<(), DeleteError> {
        todo!()
    }

    fn exists(&self, path: &Path) -> Result<bool, OpenReadError> {
        todo!()
    }

    fn open_write(&self, path: &Path) -> Result<WritePtr, OpenWriteError> {
        todo!()
    }

    fn atomic_read(&self, path: &Path) -> Result<Vec<u8>, OpenReadError> {
        todo!()
    }

    fn atomic_write(&self, path: &Path, data: &[u8]) -> std::io::Result<()> {
        todo!()
    }

    fn sync_directory(&self) -> std::io::Result<()> {
        todo!()
    }

    fn watch(&self, watch_callback: WatchCallback) -> tantivy::Result<WatchHandle> {
        todo!()
    }
}
