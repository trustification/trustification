use tracing_bunyan_formatter::BunyanFormattingLayer;

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Tracing {
    Disabled,
    Jaeger,
}

impl From<bool> for Tracing {
    fn from(enable: bool) -> Self {
        if enable {
            Tracing::Jaeger
        } else {
            Tracing::Disabled
        }
    }
}

impl Default for Tracing {
    fn default() -> Self {
        Self::Disabled
    }
}

/// Try getting the sampling rate from the environment variables
fn sampling_from_env() -> Option<f64> {
    std::env::var_os("OTEL_TRACES_SAMPLER_ARG").and_then(|s| s.to_str().map(|s| s.parse::<f64>().ok()).unwrap())
}

fn sampler() -> opentelemetry::sdk::trace::Sampler {
    if let Some(p) = sampling_from_env() {
        opentelemetry::sdk::trace::Sampler::TraceIdRatioBased(p)
    } else {
        opentelemetry::sdk::trace::Sampler::TraceIdRatioBased(0.001)
    }
}

pub fn init_tracing(name: &str, tracing: Tracing) {
    match tracing {
        Tracing::Disabled => {
            init_no_tracing();
        }
        Tracing::Jaeger => {
            init_jaeger(name);
        }
    }
}

fn init_jaeger(name: &str) {
    use tracing_subscriber::prelude::*;

    opentelemetry::global::set_text_map_propagator(opentelemetry::sdk::propagation::TraceContextPropagator::new());
    let pipeline = opentelemetry_jaeger::new_agent_pipeline()
        .with_service_name(name)
        .with_auto_split_batch(true)
        .with_trace_config(
            opentelemetry::sdk::trace::Config::default()
                .with_sampler(opentelemetry::sdk::trace::Sampler::ParentBased(Box::new(sampler()))),
        );

    println!("Using Jaeger tracing.");
    println!("{:#?}", pipeline);
    println!("Tracing is enabled. This console will not show any logging information.");

    let tracer = pipeline.install_batch(opentelemetry::runtime::Tokio).unwrap();

    let formatting_layer = BunyanFormattingLayer::new(name.to_string(), std::io::stdout);

    if let Err(e) = tracing_subscriber::Registry::default()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .with(formatting_layer)
        .try_init()
    {
        eprintln!("Error initializing tracing: {:?}", e);
    }
}

fn init_no_tracing() {
    if let Err(e) = env_logger::builder().format_timestamp_millis().try_init() {
        eprintln!("Error initializing logging: {:?}", e);
    }
}
