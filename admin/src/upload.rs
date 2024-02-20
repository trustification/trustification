use std::path::PathBuf;
use std::process::ExitCode;

use reqwest::header::HeaderMap;
use reqwest::StatusCode;
use trustification_auth::client::OpenIdTokenProviderConfigArguments;
use trustification_auth::client::TokenInjector;
use trustification_auth::client::TokenProvider;
use trustification_infrastructure::endpoint;
use trustification_infrastructure::endpoint::Endpoint;
use url::Url;

/// Upload documents to trustification
#[derive(clap::Subcommand, Debug)]
pub enum Upload {
    Bombastic(BombasticUpload),
    Vexination(VexinationUpload),
}

impl Upload {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        match self {
            Self::Bombastic(run) => run.run().await,
            Self::Vexination(run) => run.run().await,
        }
    }
}

#[derive(clap::Args, Debug)]
#[command(about = "Upload documents to Bombastic", args_conflicts_with_subcommands = true)]
pub struct BombasticUpload {
    /// URL of the Bombastic instance
    #[arg(short = 'u', long = "url", default_value_t = endpoint::Bombastic::url())]
    pub url: Url,

    /// Path to SBOM file
    #[arg(short = 'f', long = "file")]
    pub file: PathBuf,

    /// Additional headers
    #[arg(short = 'H', long = "header")]
    pub headers: Option<Vec<String>>,

    /// OIDC parameters
    #[command(flatten)]
    pub oidc: OpenIdTokenProviderConfigArguments,

    /// Development mode
    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,
}

impl BombasticUpload {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let client = reqwest::Client::new();
        let provider = self.oidc.clone().into_provider_or_devmode(self.devmode).await?;

        let data = std::fs::read(&self.file)?;
        upload(
            &format!("{}api/v1/sbom", self.url),
            &client,
            &provider,
            data,
            self.headers.unwrap_or_default(),
            self.file.file_name().map(|s| s.to_string_lossy().to_string()),
        )
        .await?;

        Ok(ExitCode::SUCCESS)
    }
}

#[derive(clap::Args, Debug)]
#[command(about = "Upload documents to Vexination", args_conflicts_with_subcommands = true)]
pub struct VexinationUpload {
    /// URL of the Vexination instance
    #[arg(short = 'u', long = "url", default_value_t = endpoint::Vexination::url())]
    pub url: Url,

    /// Path to VEX file
    #[arg(short = 'f', long = "file")]
    pub file: PathBuf,

    /// Additional headers
    #[arg(short = 'H', long = "header")]
    pub headers: Option<Vec<String>>,

    /// OIDC parameters
    #[command(flatten)]
    pub oidc: OpenIdTokenProviderConfigArguments,

    /// Development mode
    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,
}

impl VexinationUpload {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let client = reqwest::Client::new();
        let provider = self.oidc.clone().into_provider_or_devmode(self.devmode).await?;

        let data = std::fs::read(&self.file)?;
        upload(
            &format!("{}api/v1/vex", self.url),
            &client,
            &provider,
            data,
            self.headers.unwrap_or_default(),
            None,
        )
        .await?;

        Ok(ExitCode::SUCCESS)
    }
}

async fn upload(
    url: &str,
    client: &reqwest::Client,
    provider: &impl TokenProvider,
    data: Vec<u8>,
    headers: Vec<String>,
    id: Option<String>,
) -> anyhow::Result<()> {
    let mut builder = client.post(url);
    if let Some(id) = id {
        builder = builder.query(&[("id", id)]);
    }
    builder = builder.inject_token(provider).await?;

    let headers: HeaderMap = headers
        .iter()
        .map(|s| {
            let mut parts = s.splitn(2, ':');
            let key = parts.next().unwrap().trim();
            let value = parts.next().unwrap().trim();
            (key.parse().unwrap(), value.parse().unwrap())
        })
        .collect();
    builder = builder.headers(headers);
    builder = builder.body(data);

    let r = builder.send().await?;
    if r.status() == StatusCode::OK || r.status() == StatusCode::CREATED {
        log::info!("Upload successful");
        Ok(())
    } else {
        Err(anyhow::anyhow!("Upload failed: {}", r.status()))
    }
}
