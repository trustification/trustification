use crate::common::project_root;
use crate::config::TestConfig;
use globset::Glob;
use reqwest::blocking::get;
use std::fs;
use std::path::Path;
use std::process::{Child, Command};
use std::thread::sleep;
use std::time::Duration;
use walkdir::WalkDir;
use xshell::cmd;

#[derive(Clone, Copy, Debug, strum::EnumString, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum WebDriver {
    /// Don't start any webdriver
    None,
    /// Start chromedriver
    Chrome,
}

#[derive(Debug, enumset::EnumSetType, strum::EnumString, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum TestSet {
    /// Unit tests
    Unit,
    /// Integration tests
    Integ,
}

#[derive(Debug, clap::Parser)]
pub struct Test {
    /// Number of concurrent threads. Zero means: unbound
    #[arg(short, long, env, default_value_t = 0)]
    pub(crate) concurrent: usize,

    /// Number of cargo build jobs. Zero means: the number of logical CPUs
    #[arg(short, long, default_value_t = 0)]
    pub(crate) jobs: usize,

    /// Enable UI tests
    #[arg(long, env)]
    ui: bool,

    /// Port of the (chrome/gecko)driver
    #[arg(long, env, default_value_t = 4444)]
    webdriver_port: u16,

    /// Port of the (chrome/gecko)driver
    #[arg(long, env, default_value = "chrome")]
    webdriver: WebDriver,

    /// Test module
    #[arg(long)]
    pub(crate) test: Option<String>,

    /// Tests to run
    #[arg()]
    pub(crate) tests: Vec<String>,

    /// Specify a test set to run
    ///
    /// A test set is a one of `unit` (for unit tests) or `integ` (for integration
    /// tests). A comma separated list is accepted. The option can be given
    /// multiple times on the command line (its values are appended to the result
    /// list). No option given means all test sets are run (the default behavior)
    #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append, verbatim_doc_comment)]
    pub(crate) testset: Vec<TestSet>,

    /// Specify a test set to exclude
    ///
    /// A test set is a one of `unit` (for unit tests) or `integ` (for integration
    /// tests). A comma separated list is accepted. The option can be given
    /// multiple times on the command line (its values are appended to the result
    /// list)
    #[arg(long, short = 'x', value_delimiter = ',', action = clap::ArgAction::Append, verbatim_doc_comment)]
    pub(crate) exclude: Vec<TestSet>,

    /// Skip build
    #[arg(long, default_value_t = false)]
    skip_build: bool,

    /// Enable `--nocapture`
    #[arg(long, default_value_t = false)]
    pub(crate) nocapture: bool,

    /// Disable generating code coverage reports
    #[arg(long, default_value_t = false)]
    pub(crate) nocoverage: bool,
}

impl Test {
    pub fn run(&self) -> anyhow::Result<()> {
        let sh = xshell::Shell::new()?;
        let mut config = TestConfig::try_from(self)?;

        if !config.have_tests() {
            println!("No tests to run, quitting.");
            return Ok(());
        }

        sh.change_dir(project_root());
        if let Err(e) = Self::setup_coverage(&sh, &mut config) {
            eprintln!(
                "Error: {e}\n\n\
                Disabling coverage due to the previous error."
            );
            config.nocoverage = true;
        }
        let _webdriver = self.setup_webdriver(&sh, &mut config).unwrap_or_else(|e| {
            eprintln!(
                "Error: {e}\n\n\
                User interface tests will be skipped due to the previous error."
            );
            Shutdown(None)
        });

        let units_result = self.run_units(&sh, &config);
        let integs_result = self.run_integs(&sh, &config);

        // Do not generate coverage reports if any test fails
        units_result.and(integs_result)?;

        Self::report_coverage(&sh, &config)
    }

    pub fn run_units(&self, sh: &xshell::Shell, config: &TestConfig) -> anyhow::Result<()> {
        if !config.testset.contains(TestSet::Unit) {
            return Ok(());
        }

        CargoTest::new().run(sh, config)
    }

    pub fn run_integs(&self, sh: &xshell::Shell, config: &TestConfig) -> anyhow::Result<()> {
        if !config.testset.contains(TestSet::Integ) {
            return Ok(());
        }

        CargoTest::new()
            .module("integration-tests".to_string())
            .with_features()
            .run(sh, config)
    }

    // Setup test environment for generating code coverage reports.
    //
    // * Clean old profiling data and coverage reports.
    // * Create appropriate directories.
    // * Check whether the expected tools are installed.
    pub fn setup_coverage(sh: &xshell::Shell, config: &mut TestConfig) -> anyhow::Result<()> {
        if config.nocoverage {
            return Ok(());
        }

        Self::cleanup_profdata(sh)?;
        Self::setup_coverage_dirs(sh)?;
        config.find_tool(TestConfig::LLVM_PROFDATA)?;
        config.find_tool(TestConfig::LLVM_COV)?;
        config.find_tool(TestConfig::GRCOV)?;
        Ok(())
    }

    // Find and spawn a web driver.
    //
    // If a web driver is successfully spawned, enable user interface tests and
    // return the web driver's wrapped process id which will be freed
    // automatically at the end of its scope.
    pub fn setup_webdriver(&self, sh: &xshell::Shell, config: &mut TestConfig) -> anyhow::Result<Shutdown> {
        // Do not launch webdriver when integration tests are excluded
        if !config.testset.contains(TestSet::Integ) {
            return Ok(Shutdown(None));
        }

        Ok(Shutdown(match self.ui {
            true => {
                config.find_webdriver(self.webdriver)?;

                // Try to build Spog UI when requested, quit early in case
                // of error
                if !self.skip_build {
                    let npm = TestConfig::NPM;
                    let trunk_ng = TestConfig::TRUNK_NG;

                    config.find_tool(npm)?;
                    config.find_tool(trunk_ng)?;
                    config.check_target(sh, TestConfig::WASM32_UNKNOWN_UNKNOWN)?;

                    let _dir = sh.push_dir("spog/ui");
                    let _env = sh.push_env("PATH", &config.paths);
                    cmd!(sh, "{npm} ci").run()?;
                    cmd!(sh, "{trunk_ng} build").run()?;
                }

                // Try to spawn a web driver. In case of success enable user
                // interface tests in integration tests, quit otherwise
                match self.webdriver {
                    WebDriver::None => None,
                    WebDriver::Chrome => {
                        let port = self.webdriver_port;
                        let webdriver = Command::new(TestConfig::CHROME)
                            .env("PATH", &config.paths)
                            .arg(format!("--port={port}"))
                            .spawn()?;

                        loop {
                            println!("Checking if webdriver is up...");
                            if get(format!("http://localhost:{port}/status"))
                                .and_then(|r| r.error_for_status())
                                .is_ok()
                            {
                                break;
                            }
                            sleep(Duration::from_secs(1));
                        }

                        config.features.extend(["--features".to_string(), "ui".to_string()]);
                        Some(webdriver)
                    }
                }
            }
            false => None,
        }))
    }

    // Remove all `cargo-test-*.profraw` files so they will not interfere with
    // new coverage results.
    pub fn cleanup_profdata(sh: &xshell::Shell) -> anyhow::Result<()> {
        let glob = Glob::new(TestConfig::LLVM_PROFILE_FILE_GLOB)?.compile_matcher();

        for entry in WalkDir::new(sh.current_dir()) {
            let entry = entry?.clone();
            let path = entry.path();

            // .filer_item gives wrong results even with .contents_first(true)
            if glob.is_match(path) {
                sh.remove_path(path)?;
            }
        }
        Ok(())
    }

    // Setup directories used during coverage.
    //
    // Currently clear/recreate a directory with coverage reports.
    pub fn setup_coverage_dirs(sh: &xshell::Shell) -> anyhow::Result<()> {
        let path = sh.current_dir().join(TestConfig::COVERAGE_DIR);

        if path.try_exists()? {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(())
    }

    // Generate coverage reports
    pub fn report_coverage(sh: &xshell::Shell, config: &TestConfig) -> anyhow::Result<()> {
        if config.nocoverage {
            return Ok(());
        }

        let target_dir = TestConfig::TARGET_COV_DIR;
        let mut args = vec![
            "--log-level".to_string(),
            "INFO".to_string(),
            "--source-dir".to_string(),
            ".".to_string(),
            "--binary-path".to_string(),
            format!("./{target_dir}/debug/deps"),
            "--llvm-path".to_string(),
            config.llvm_path.to_str().unwrap().to_string(),
            "--output-types".to_string(),
            "files,markdown,html".to_string(),
            "--branch".to_string(),
            "--ignore-not-existing".to_string(),
            "--ignore".to_string(),
            "/*".to_string(),
            "--ignore".to_string(),
            "integration-tests/*".to_string(),
            "--ignore".to_string(),
            "xtask/*".to_string(),
            "--output-path".to_string(),
            TestConfig::COVERAGE_DIR.to_string(),
        ];
        let profdata_dir = Path::new(TestConfig::LLVM_PROFILE_FILE).parent().map(|p| p.as_os_str());
        for entry in WalkDir::new(sh.current_dir()).into_iter() {
            let entry = entry?.clone();
            let path = entry.path();

            // .filer_item gives wrong results even with .contents_first(true)
            if path.is_dir() && path.file_name() == profdata_dir {
                args.push(path.to_str().unwrap().to_string());
            }
        }

        sh.cmd("grcov").env("PATH", config.paths.clone()).args(args).run()?;
        Ok(())
    }
}

// `cargo test ...` command builder.
struct CargoTest {
    module: Option<String>,
    features: bool,
}

impl CargoTest {
    pub fn new() -> Self {
        Self {
            module: None,
            features: false,
        }
    }

    pub fn module(mut self, name: String) -> Self {
        self.module = Some(name);
        self
    }

    pub fn with_features(mut self) -> Self {
        self.features = true;
        self
    }

    pub fn run(&self, sh: &xshell::Shell, config: &TestConfig) -> anyhow::Result<()> {
        let mut envs = vec![];
        let mut args = vec![];

        envs.push(("PATH", config.paths.clone()));
        if !config.nocoverage {
            envs.extend([
                // Changing `RUSTFLAGS` will change the fingerprint. `xtask` and
                // tests are sharing some dependencies but they are also compiled
                // with different `RUSTFLAGS`. As a consequence, `cargo` recompiles
                // everything again during every run of `xtask` because of repeatedly
                // changing fingerprints. To prevent this, we use a different
                // target directory for tests and their dependencies when code
                // coverage is enabled.
                ("CARGO_TARGET_DIR", TestConfig::TARGET_COV_DIR.to_string()),
                ("RUSTFLAGS", "-Cinstrument-coverage".to_string()),
                ("LLVM_PROFILE_FILE", TestConfig::LLVM_PROFILE_FILE.to_string()),
            ])
        }

        args.push("test");
        if let Some(module) = &self.module {
            args.extend(["-p", module]);
        }
        args.extend(config.opts.iter().map(|e| e.as_str()));
        if self.features {
            args.extend(config.features.iter().map(|e| e.as_str()));
        }
        if !config.extras.is_empty() {
            args.push("--");
            args.extend(config.extras.iter().map(|e| e.as_str()));
        }

        sh.cmd("cargo").envs(envs).args(args).run()?;
        Ok(())
    }
}

pub struct Shutdown(Option<Child>);

impl Drop for Shutdown {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            if let Err(err) = child.kill() {
                eprintln!("Failed to kill webdriver: {err}");
            }
            child.wait().unwrap();
        }
    }
}
