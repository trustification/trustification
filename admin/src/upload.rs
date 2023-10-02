use std::path::PathBuf;
use std::process::ExitCode;

use reqwest::StatusCode;
use trustification_auth::client::OpenIdTokenProviderConfigArguments;
use trustification_auth::client::TokenInjector;
use trustification_auth::client::TokenProvider;
use url::Url;

/// Uplaod documents to trustification
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
    #[arg(short = 'u', long = "url", default_value = "http://localhost:8080/api/v1/sbom")]
    pub url: Url,

    /// Path to SBOM file
    #[arg(short = 'f', long = "file")]
    pub file: PathBuf,

    /// OIDC parameters
    #[command(flatten)]
    pub oidc: OpenIdTokenProviderConfigArguments,
}

impl BombasticUpload {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let client = reqwest::Client::new();
        let provider = self.oidc.clone().into_provider_or_devmode(false).await?;

        let data = std::fs::read(&self.file)?;
        upload(
            &self.url,
            &client,
            &provider,
            data,
            self.file.file_name().map(|s| s.to_string_lossy().to_string()),
        )
        .await?;

        Ok(ExitCode::SUCCESS)
    }
}

#[derive(clap::Args, Debug)]
#[command(about = "Upload documents to Vexination", args_conflicts_with_subcommands = true)]
pub struct VexinationUpload {
    /// URL of the Bombastic instance
    #[arg(short = 'u', long = "url", default_value = "http://localhost:8080/api/v1/vex")]
    pub url: Url,

    /// Path to VEX file
    #[arg(short = 'f', long = "file")]
    pub file: PathBuf,

    /// OIDC parameters
    #[command(flatten)]
    pub oidc: OpenIdTokenProviderConfigArguments,
}

impl VexinationUpload {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let client = reqwest::Client::new();
        let provider = self.oidc.clone().into_provider_or_devmode(false).await?;

        let data = std::fs::read(&self.file)?;
        upload(&self.url, &client, &provider, data, None).await?;

        Ok(ExitCode::SUCCESS)
    }
}

async fn upload(
    url: &url::Url,
    client: &reqwest::Client,
    provider: &impl TokenProvider,
    data: Vec<u8>,
    id: Option<String>,
) -> anyhow::Result<()> {
    let mut builder = client.post(url.clone());
    if let Some(id) = id {
        builder = builder.query(&[("id", id)]);
    }
    builder = builder.inject_token(provider).await?;
    builder = builder.body(data);

    match builder.send().await {
        Ok(r) if r.status() == StatusCode::OK || r.status() == StatusCode::CREATED => {
            log::info!("Upload successful");
        }
        Ok(r) => {
            log::warn!("Failed to upload document: {}", r.status());
        }
        Err(e) => {
            log::warn!("Failed to upload document: {e}");
        }
    }
    Ok(())
}
