use std::net::SocketAddr;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use futures::future::join;
use guac::collectsub::{CollectSubClient, Entry, Filter};
use tokio::time::interval;

use trustification_infrastructure::{Infrastructure, InfrastructureConfig};

mod request;
mod server;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(short, long, default_value = "0.0.0.0")]
    pub bind: String,

    #[arg(short = 'p', long = "port", default_value_t = 9919)]
    pub port: u16,

    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    #[arg(short = 'u', long = "csub-url", default_value = "http://localhost:2782/")]
    pub(crate) csub_url: String,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let infra = Infrastructure::from(self.infra).run("collectorist-api", |_metrics| async move {
            let state = Self::configure()?;
            let addr = SocketAddr::from_str(&format!("{}:{}", self.bind, self.port))?;

            server::run(state, addr).await
        });

        let mut csub = CollectSubClient::new(self.csub_url).await?;

        let mut sleep = interval(tokio::time::Duration::from_millis(1000));

        let listener = async move {
            let mut since_time = SystemTime::UNIX_EPOCH;
            loop {
                let nowish = SystemTime::now();
                let filters = vec![Filter::Purl("*".into())];
                let results = csub.get(filters, since_time).await;
                since_time = nowish;
                if let Ok(results) = results {
                    for entry in &results {
                        match entry {
                            Entry::Unknown(_) => {}
                            Entry::Git(_) => {}
                            Entry::Oci(_) => {}
                            Entry::Purl(purl) => {
                                println!("purl: {}", purl);
                            }
                            Entry::GithubRelease(_) => {}
                        }
                    }
                }
                sleep.tick().await;
            }
        };

        let _ = join(listener, infra).await;

        Ok(ExitCode::SUCCESS)
    }

    fn configure() -> anyhow::Result<Arc<AppState>> {
        let state = Arc::new(AppState {});

        Ok(state)
    }
}

pub struct AppState {}

pub(crate) type SharedState = Arc<AppState>;
