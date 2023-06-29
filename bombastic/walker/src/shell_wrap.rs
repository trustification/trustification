use std::io;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use url::Url;

#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct ScriptContext {
    /// Path to shell scripts
    #[arg(long = "scripts-path", default_value = "bombastic/walker/")]
    path: PathBuf,

    /// Path to a writeable working directory
    #[arg(long = "workdir", default_value = "./")]
    workdir: Option<PathBuf>,
}

const DEFAULT_GPG_KEY_SOURCE: &str =
    "https://access.redhat.com/sites/default/files/pages/attachments/dce3823597f5eac4.txt";

impl ScriptContext {
    pub fn bombastic_upload(&self, sbom_path: &Url, bombastic: &Url) {
        // find the script location
        let script_path = self.path.join(PathBuf::from("./walker.sh"));
        let mut cmd = Command::new(script_path);

        if let Some(path) = &self.workdir {
            cmd.arg("-w").arg(path);
        }

        let result = cmd
            .arg(sbom_path.as_str())
            .arg(bombastic.as_str())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .output();

        log_script_output(result, "walker.sh");
    }

    pub fn setup_gpg(&self, key_address: Option<&Url>) -> Result<(), anyhow::Error> {
        let address = key_address.map_or(DEFAULT_GPG_KEY_SOURCE, |s| s.as_str());
        let script_path = self.path.join(PathBuf::from("setup_gpg_key.sh"));

        let mut cmd = Command::new(script_path);
        if let Some(path) = &self.workdir {
            cmd.arg("-w").arg(path);
        }

        let log = cmd
            .arg(address)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .output();

        log_script_output(log, "setup_gpg_key.sh");
        Ok(())
    }
}

pub fn log_script_output(log: io::Result<Output>, script_name: &str) {
    match log {
        Ok(r) => {
            for line in String::from_utf8_lossy(&r.stdout).split('\n') {
                if !line.is_empty() {
                    tracing::info!("{script_name}: {line}");
                }
            }
        }
        Err(e) => tracing::error!("{script_name}: {e}"),
    }
}
