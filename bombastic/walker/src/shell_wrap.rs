use std::io;
use std::io::ErrorKind;
use std::process::{Command, Output, Stdio};
use url::Url;

pub fn run(script_path: &str, path: &Url, bombastic: &Url) {
    let result = Command::new(script_path)
        .arg(path.as_str())
        .arg(bombastic.as_str())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output();

    log_script_output(result, "walker.sh");
}

const DEFAULT_GPG_KEY_SOURCE: &str =
    "https://access.redhat.com/sites/default/files/pages/attachments/dce3823597f5eac4.txt";

pub fn setup_gpg(key_address: Option<&Url>) -> Result<(), anyhow::Error> {
    let address = key_address.map_or(DEFAULT_GPG_KEY_SOURCE, |s| s.as_str());

    let script_path = script_path("setup_gpg_key.sh")?;

    let log = Command::new(script_path)
        .arg(address)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output();

    log_script_output(log, "setup_gpg_key.sh");
    Ok(())
}

pub fn script_path(name: &str) -> Result<String, io::Error> {
    // ubi-minimal don't have which so we try to start the script
    let which = Command::new(name).arg("-h").output();

    match which {
        Ok(_) => Ok(String::from(name)),
        // If the script is not found we assume the workdir is the cargo root
        Err(e) => match e.kind() {
            ErrorKind::NotFound => {
                let mut default_path = String::from("bombastic/walker/");
                default_path.push_str(name);

                Ok(default_path)
            }
            _ => Err(e),
        },
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
