use std::io;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use url::Url;

#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct ScriptContext {
    /// Path to shell scripts
    #[arg(long = "scripts_path")]
    path: Option<PathBuf>,

    /// Path to a writeable working directory
    #[arg(long = "workdir", default_value = "./")]
    workdir: Option<PathBuf>,
}

const DEFAULT_GPG_KEY_SOURCE: &str =
    "https://access.redhat.com/sites/default/files/pages/attachments/dce3823597f5eac4.txt";

impl ScriptContext {
    pub fn bombastic_upload(&self, sbom_path: &Url, bombastic: &Url, script_path: &PathBuf) {
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
        let script_path = self.script_path("./setup_gpg_key.sh")?;

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

    pub fn script_path(&self, name: &str) -> Result<PathBuf, io::Error> {
        if let Some(path) = &self.path {
            let path = path.join(PathBuf::from(name));
            return Ok(path);
        }

        // ubi-minimal don't have which so we try to start the script
        let which = Command::new(name).arg("-h").output();

        match which {
            Ok(_) => Ok(PathBuf::from(name)),
            // If the script is not found we assume the workdir is the cargo root
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    let mut default_path = PathBuf::from("bombastic/walker/");
                    default_path.push(name);

                    Ok(default_path)
                }
                _ => {
                    tracing::error!("{name}: {e}");
                    Err(e)
                }
            },
        }
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
