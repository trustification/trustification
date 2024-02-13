use crate::config::TestConfig;
use std::{error, fmt};

#[derive(Clone, Debug)]
pub enum Error {
    ToolMissingError(String),
    TargetMissingError(String),
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ToolMissingError(tool) => match tool.as_str() {
                TestConfig::LLVM_PROFDATA | TestConfig::LLVM_COV => write!(
                    f,
                    "LLVM tools are not installed.\n\n\
                    Hint: You can use `rustup component add llvm-tools-preview`\n\
                    or `dnf install llvm` (Fedora/CentOS/RHEL) to get them."
                ),
                _ => write!(f, "`{tool}` is not installed.{}", hint(tool)),
            },
            Error::TargetMissingError(target) => write!(
                f,
                "Target `{target}` is not installed.\n\n\
                Hint: You can use `rustup target add {target}` to install `{target}` target."
            ),
        }
    }
}

fn hint(tool: &String) -> String {
    match tool.as_str() {
        TestConfig::GRCOV | TestConfig::NPM | TestConfig::TRUNK | TestConfig::CHROME => {
            format!("\n\nHint: To get {tool}, run {}.", install_cmd(tool))
        }
        TestConfig::RUSTUP => {
            format!(
                "\n\nHint: You are probably using a distro-specific installation of Rust.\n\
                To build and run tests it is recommended to use Rust installed locally via `{tool}`\n\
                (please follow https://www.rust-lang.org/tools/install for more info)."
            )
        }
        _ => String::from(""),
    }
}

fn install_cmd(tool: &String) -> String {
    match tool.as_str() {
        TestConfig::GRCOV | TestConfig::TRUNK => format!("`cargo install {tool}`"),
        TestConfig::NPM | TestConfig::CHROME => format!(
            "`dnf install {}` (Fedora/CentOS/RHEL)",
            match tool.as_str() {
                TestConfig::NPM => "nodejs-npm",
                _ => tool,
            },
        ),
        _ => String::from("???"),
    }
}
