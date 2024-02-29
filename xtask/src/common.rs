use std::path::{Path, PathBuf};

pub fn project_root() -> Option<PathBuf> {
    Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .map(|path| path.to_path_buf())
}
