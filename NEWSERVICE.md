# Creating a new microservice

So, you want to create a new microservice in Trustification, great! When adding a new microservice, you should add metrics, authentication and authorization.

You should also allow the microservice to run from the `trust` binary as a subcommand which will make it available in the released binaries and the container image automatically.

## Linking into the main application

Starting with this point makes the rest easier. Your microservice should use `clap` to define a set of command line arguments that it needs as well as a run() function:

```rust
#[derive(clap::Args, Debug)]
#[command(about = "Run the service", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,
}

impl Run {
    pub async fn run(mut self) -> anyhow::Result<ExitCode> {
        // TODO: Your code here
    }
}
```

Once you have this in place, you can add a dependency to your microservice in the `main.rs` in the `trust` crate and link it into the command line arguments as a subcommand:

```rust
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    #[command(subcommand)]
    Vexination(vexination::Command),
    Exporter(exporter::Run),

    ...
    
    // LOOK!
    MyService(myservice::Run)
}
```

With that in place, you can start to add metrics and auth.

## Metrics

Using the `trustification-infrastructure` crate, you automatically get an HTTP endpoint exposed on localhost which can be used as liveness/readiness probe as well as a metrics endpoints. 

To enable the infrastructure, first add the InfrastructureConfig to your command line arguments:

```rust
#[derive(clap::Args, Debug)]
#[command(about = "Run the service", args_conflicts_with_subcommands = true)]
pub struct Run {
    ...

    #[command(flatten)]
    pub infra: InfrastructureConfig,

    ...
}
```

Your app should configure itself in the closure provided to the infrastructure:

```rust
    pub async fn run(mut self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run("my-service", |metrics| async move {

                // The `prometheus` crate is required to register metrics with the metrics instance.
                let indexed_total = prometheus::register_int_counter_with_registry!(
                    opts!("index_indexed_total", "Total number of indexing operations"),
                    registry);

                // TODO: your code here

                Ok(())
            })
            .await?;
    }
```

See the [prometheus documentation](https://docs.rs/prometheus/latest/prometheus/) on how to use the registry to register metrics.

## Authentication/Authorization

In the same way as metrics, authentication using OIDC requires some additional config to your application:

```rust
    #[command(flatten)]
    pub auth: AuthConfigArguments,
```

With this you can create an authenticator in your run method and setup your Actix HTTP server:

```rust
impl Run {
    pub async fn run(mut self) -> anyhow::Result<ExitCode> {

        let (authn, authz) = self.auth.split(self.devmode)?.unzip();
        let authenticator: Option<Arc<Authenticator>> = Authenticator::from_config(authn).await?.map(Arc::new);
        let authorizer = Authorizer::new(authz);

        Infrastructure::from(self.infra)
            .run("my-service", |metrics| async move {

                let http_metrics = PrometheusMetricsBuilder::new("my_api")
                    .registry(metrics.registry().clone())
                    .build()
                    .map_err(|_| anyhow!("Error registering HTTP metrics"))?;

                let mut srv = HttpServer::new(move || {
                    let http_metrics = http_metrics.clone();
                    let cors = Cors::permissive();
                    let authenticator = authenticator.clone();
                    let authorizer = authorizer.clone();

                    new_app(AppOptions {
                        cors: Some(cors),
                        metrics: Some(http_metrics),
                        // Enable authentication for all services. If you need this only for individual services, then
                        // use `None`, and add the authenticator manually to services (see below).
                        authenticator,
                        authorizer,
                    })
                    // NOTE: Request will fail before invoking this handler if authentication is enabled
                    .service(hello)
                    // Alternative way, adding authentication to only one service.
                    .service(web::scope("/api/v1")
                        .wrap(new_auth!(auth))
                        .service(hello),
                    )
                });

                Ok(())
            })
            .await?;
    }
}

#[get("/")]
async fn hello(
    authorizer: web::Data<Authorizer>,
    user: UserInformation)
{
    // Fails if user does not have the manager role.
    authorizer.require_role(user, ROLE_MANAGER)?;
}
```

## Further examples

For more examples on the above, see the [bombastic-indexer](https://github.com/trustification/trustification/tree/main/bombastic/indexer) or 
[spog](https://github.com/trustification/trustification/tree/main/spog/api) services.
