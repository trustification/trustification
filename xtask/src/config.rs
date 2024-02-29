use crate::errors::Error;
use crate::task::{Test, TestSet, WebDriver};
use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Command;
use which::which_in_global;
use xshell::cmd;

#[derive(Debug)]
pub struct TestConfig {
    pub(crate) opts: Vec<String>,
    pub(crate) features: Vec<String>,
    pub(crate) extras: Vec<String>,
    pub(crate) testset: enumset::EnumSet<TestSet>,
    pub(crate) nocoverage: bool,
    pub(crate) paths: String,
    pub(crate) llvm_path: PathBuf,
}

impl TestConfig {
    pub const RUSTC: &'static str = "rustc";
    pub const RUSTUP: &'static str = "rustup";
    pub const WASM32_UNKNOWN_UNKNOWN: &'static str = "wasm32-unknown-unknown";
    pub const LLVM_PROFILE_FILE: &'static str = ".profdata/cargo-test-%p-%m.profraw";
    pub const LLVM_PROFILE_FILE_GLOB: &'static str = "**/cargo-test-*.profraw";
    pub const COVERAGE_DIR: &'static str = ".coverage";
    pub const TARGET_COV_DIR: &'static str = "target.cov";
    pub const LLVM_PROFDATA: &'static str = "llvm-profdata";
    pub const LLVM_COV: &'static str = "llvm-cov";
    pub const GRCOV: &'static str = "grcov";
    pub const NPM: &'static str = "npm";
    pub const TRUNK: &'static str = "trunk";
    pub const CHROME: &'static str = "chromedriver";

    pub fn new() -> Self {
        Self {
            opts: Vec::<String>::new(),
            features: Vec::<String>::new(),
            extras: Vec::<String>::new(),
            testset: enumset::EnumSet::<TestSet>::new(),
            nocoverage: false,
            paths: String::new(),
            llvm_path: PathBuf::new(),
        }
    }

    // Any test to run?
    pub fn have_tests(&self) -> bool {
        !self.testset.is_empty()
    }

    // Try to find tool in `$(rustc --print target-libdir)/../bin:${HOME}/.cargo/bin:${PATH}`.
    //
    // When looking for LLVM tool, update `llvm_path` needed later by `grcov`.
    // The value of `$(rustc --print target-libdir)/../bin:${HOME}/.cargo/bin:${PATH}`
    // is precomputed by `try_from` and saved to `paths`.
    pub fn find_tool<T: AsRef<OsStr>>(&mut self, name: T) -> anyhow::Result<PathBuf> {
        let tool = String::from(name.as_ref().to_str().unwrap());

        Ok(which_in_global(name, Some(self.paths.clone()))
            .map_err(|_| Error::ToolMissingError(tool.clone()))
            .and_then(|mut i| i.next().ok_or(Error::ToolMissingError(tool.clone())))
            .map(|p| match tool.as_str() {
                Self::LLVM_PROFDATA | Self::LLVM_COV => {
                    // Save the path to LLVM tools for `grcov`
                    // `p.parent()` should be always `Some(value)`
                    self.llvm_path.push(p.parent().unwrap());
                    p
                }
                _ => p,
            })?)
    }

    // Check whether the requested web driver is installed.
    pub fn find_webdriver(&mut self, webdriver: WebDriver) -> anyhow::Result<Option<PathBuf>> {
        match webdriver {
            WebDriver::None => Ok(None),
            WebDriver::Chrome => self.find_tool(Self::CHROME).map(Some),
        }
    }

    // Check whether the requested target is installed.
    pub fn check_target<T: AsRef<str>>(&mut self, sh: &xshell::Shell, name: T) -> anyhow::Result<()> {
        let rustup = Self::RUSTUP;

        self.find_tool(rustup)?;

        let target = name.as_ref();
        let _env = sh.push_env("PATH", &self.paths);
        if !cmd!(sh, "{rustup} target list --installed").read()?.contains(target) {
            return Err(Error::TargetMissingError(String::from(target)).into());
        }
        Ok(())
    }
}

impl Default for TestConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<&Test> for TestConfig {
    type Error = anyhow::Error;

    // Make test configuration from test arguments.
    //
    // In greater detail:
    // - collect tests and their parameters
    // - precompute the value of `${HOME}/.cargo/bin;${PATH}`
    fn try_from(args: &Test) -> anyhow::Result<Self> {
        let mut config = Self::new();

        if args.jobs > 0 {
            config.opts.extend(["--jobs".to_string(), args.jobs.to_string()]);
        }
        if args.nocapture {
            config.extras.push("--nocapture".to_string());
        }
        if args.concurrent > 0 {
            config
                .extras
                .extend(["--test-threads".to_string(), args.concurrent.to_string()]);
        }
        args.test.iter().for_each(|v| {
            config.extras.extend(["--test".to_string(), (*v).clone()]);
        });
        config.extras.extend(args.tests.clone());
        args.testset.iter().for_each(|v| {
            config.testset.insert(*v);
        });
        if !config.have_tests() {
            config.testset.insert_all(enumset::EnumSet::<TestSet>::ALL);
        }
        args.exclude.iter().for_each(|v| {
            config.testset.remove(*v);
        });
        config.nocoverage = args.nocoverage;

        let mut paths = Vec::<PathBuf>::new();
        if let Some(home) = env::var_os("HOME") {
            let cargo_bin = format!("{}/.cargo/bin", home.to_str().unwrap());

            let mut rustc = PathBuf::from(&cargo_bin);
            rustc.push(Self::RUSTC);

            // This is where binaries appears when installed via `rustup component add ...`
            if let Ok(output) = Command::new(rustc).args(["--print", "target-libdir"]).output() {
                let target_libdir = String::from_utf8(output.stdout)?;
                let target_bindir = PathBuf::from(target_libdir.trim());
                let mut target_bindir = PathBuf::from(target_bindir.parent().unwrap());
                target_bindir.push("bin");

                paths.push(target_bindir);
            }

            paths.push(cargo_bin.into());
        }
        if let Some(path) = env::var_os("PATH") {
            paths.extend(env::split_paths(&path));
        }
        config.paths.push_str(env::join_paths(paths)?.to_str().unwrap());

        Ok(config)
    }
}
