use crate::common::project_root;
use reqwest::blocking::get;
use std::process::{Child, Command};
use std::thread::sleep;
use std::time::Duration;
use xshell::cmd;

#[derive(Clone, Copy, Debug, strum::EnumString, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum WebDriver {
    /// Don't start any webdriver
    None,
    /// Start chromedriver
    Chrome,
}

#[derive(Debug, clap::Parser)]
pub struct Test {
    /// Number of concurrent threads. Zero means: unbound.
    #[arg(short, long, env, default_value_t = 0)]
    concurrent: usize,

    /// Enable UI tests
    #[arg(long, env)]
    ui: bool,

    /// Enable guac tests
    #[arg(long, env)]
    guac: bool,

    /// Port of the (chrome/gecko)driver
    #[arg(long, env, default_value_t = 4444)]
    webdriver_port: u16,

    /// Port of the (chrome/gecko)driver
    #[arg(long, env, default_value = "chrome")]
    webdriver: WebDriver,

    /// Test module
    #[arg(long)]
    test: Option<String>,

    /// Tests to run
    #[arg()]
    tests: Vec<String>,

    /// Skip build
    #[arg(long, default_value_t = false)]
    skip_build: bool,

    /// Enable `--nocapture`
    #[arg(long, default_value_t = false)]
    nocapture: bool,
}

impl Test {
    pub fn run(self) -> anyhow::Result<()> {
        let sh = xshell::Shell::new()?;
        sh.change_dir(project_root());

        let threads = match self.concurrent {
            0 => vec![],
            n => vec!["--test-threads".to_string(), n.to_string()],
        };

        let port = self.webdriver_port;
        let mut features = vec![];

        if self.guac {
            features.extend(["--features", "guac"]);
        }

        // don't drop this until we're done with it
        let _webdriver = Shutdown(match self.ui {
            true => {
                features.extend(["--features", "ui"]);

                if !self.skip_build {
                    let _dir = sh.push_dir("spog/ui");
                    cmd!(sh, "npm ci").run()?;
                    cmd!(sh, "trunk-ng build ").run()?;
                }

                match self.webdriver {
                    WebDriver::None => None,
                    WebDriver::Chrome => {
                        let webdriver = Command::new("chromedriver").arg(format!("--port={port}")).spawn()?;

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

                        Some(webdriver)
                    }
                }
            }
            false => None,
        });

        // now run the tests

        let tests = self.tests;
        let test = self
            .test
            .iter()
            .flat_map(|test| vec!["--test", test])
            .collect::<Vec<_>>();

        let mut opts = vec![];
        if self.nocapture {
            opts.push("--nocapture");
        }

        let cmd = cmd!(
            sh,
            "cargo test -p integration-tests {features...} -- {opts...} {threads...} {test...} {tests...}"
        );

        cmd.run()?;

        Ok(())
    }
}

struct Shutdown(Option<Child>);

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
