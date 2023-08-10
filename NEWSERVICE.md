# Creating a new microservice

To create a new microservice in Trustification, you need to add metrics, authentication and authorization.

You should also expose your service in the `trust` binary as a subcommand which will make it available in the released binaries and the container image automatically.

## Metrics

Using the `trustification-infrastructure` crate, you automatically get an HTTP endpoint exposed on localhost which can be used as liveness/readiness probe as well as a metrics endpoints. Your app should configure itself in the the closure provided to the infrastructure:

```rust
let infra: InfrastructureConfig = ... // usually part of the command line arguments
Infrastructure::from(infra)
    .run("my-service", |metrics| async move {
        // The `prometheus` crate is required to register metrics with the metrics instance.
        let indexed_total = prometheus::register_int_counter_with_registry!(
            opts!("index_indexed_total", "Total number of indexing operations"),
            registry);

        // TODO: your application code
        Ok(())
    })
    .await?;
```

See the [prometheus documentation](https://docs.rs/prometheus/latest/prometheus/) on how to use the registry to register metrics.

NOTE: Actix HTTP metrics will be automatically added by the infrastructure, you don't need to configure that.

## Authentication/Authorization

## Linking into the main application
