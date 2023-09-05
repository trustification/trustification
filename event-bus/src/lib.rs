//! Event bus used in Trustification.

use prometheus::{opts, register_int_counter_vec_with_registry, IntCounterVec, Registry};

mod kafka;
mod sqs;

/// Represents an event receieved from a consumer.
#[allow(clippy::large_enum_variant)]
pub enum Event<'m> {
    Kafka(kafka::KafkaEvent<'m>),
    Sqs(sqs::SqsEvent<'m>),
}

impl<'m> Event<'m> {
    /// The event payload.
    pub fn payload(&self) -> Option<&[u8]> {
        match self {
            Self::Kafka(event) => event.payload(),
            Self::Sqs(event) => event.payload(),
        }
    }

    /// Topic in which the event was received.
    pub fn topic(&self) -> &str {
        match self {
            Self::Kafka(event) => event.topic(),
            Self::Sqs(event) => event.topic(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing parameter: {0}")]
    MissingParameter(String),
}

/// Represents an event bus instance.
pub struct EventBus {
    metrics: Metrics,
    inner: InnerBus,
}

#[derive(Clone)]
struct Metrics {
    sent_total: IntCounterVec,
    received_total: IntCounterVec,
    committed_total: IntCounterVec,
}

impl Metrics {
    fn register(registry: &Registry) -> Result<Self, anyhow::Error> {
        let sent_total = register_int_counter_vec_with_registry!(
            opts!("eventbus_sent_total", "Total number of events sent"),
            &["topic"],
            registry
        )?;

        let received_total = register_int_counter_vec_with_registry!(
            opts!("eventbus_received_total", "Total number of events received"),
            &["topic"],
            registry
        )?;

        let committed_total = register_int_counter_vec_with_registry!(
            opts!("eventbus_committed_total", "Total number of events committed"),
            &["topic"],
            registry
        )?;

        Ok(Self {
            sent_total,
            received_total,
            committed_total,
        })
    }
}

enum InnerBus {
    Kafka(kafka::KafkaEventBus),
    Sqs(sqs::SqsEventBus),
}

impl EventBus {
    /// Subscribe to a set of topics using a provided group id.
    ///
    /// For Kafka, the group id maps to a consumer group, while for SQS it is ignored.
    pub async fn subscribe(&self, group: &str, topics: &[&str]) -> Result<EventConsumer<'_>, anyhow::Error> {
        match &self.inner {
            InnerBus::Kafka(bus) => {
                let consumer = bus.subscribe(group, topics).await?;
                Ok(EventConsumer::new(InnerConsumer::Kafka(consumer), self.metrics.clone()))
            }
            InnerBus::Sqs(bus) => {
                let consumer = bus.subscribe(group, topics).await?;
                Ok(EventConsumer::new(InnerConsumer::Sqs(consumer), self.metrics.clone()))
            }
        }
    }

    /// Create a set of topics on the event bus. This assumes authorization is already setup for this to be allowed.
    pub async fn create(&self, topics: &[&str]) -> Result<(), anyhow::Error> {
        match &self.inner {
            InnerBus::Kafka(bus) => bus.create(topics).await,
            InnerBus::Sqs(bus) => bus.create(topics).await,
        }
    }

    /// Send a message to a topic on the event bus.
    pub async fn send(&self, topic: &str, data: &[u8]) -> Result<(), anyhow::Error> {
        match &self.inner {
            InnerBus::Kafka(bus) => bus.send(topic, data).await?,
            InnerBus::Sqs(bus) => bus.send(topic, data).await?,
        }
        self.metrics.sent_total.with_label_values(&[topic]).inc();
        Ok(())
    }
}

/// An event consumer belongs to a group and consumes events from multiple topics.
pub struct EventConsumer<'d> {
    metrics: Metrics,
    inner: InnerConsumer<'d>,
}

impl<'d> EventConsumer<'d> {
    fn new(inner: InnerConsumer<'d>, metrics: Metrics) -> Self {
        Self { inner, metrics }
    }
}

enum InnerConsumer<'d> {
    Kafka(kafka::KafkaConsumer),
    Sqs(sqs::SqsConsumer<'d>),
}

impl<'d> EventConsumer<'d> {
    /// Wait for the next available event on this consumers topics.
    pub async fn next<'m>(&'m self) -> Result<Option<Event<'m>>, anyhow::Error> {
        let event = match &self.inner {
            InnerConsumer::Kafka(consumer) => {
                let event = consumer.next().await?;
                event.map(Event::Kafka)
            }
            InnerConsumer::Sqs(consumer) => {
                let event = consumer.next().await?;
                event.map(Event::Sqs)
            }
        };
        if let Some(event) = &event {
            self.metrics.received_total.with_label_values(&[event.topic()]).inc();
        }
        Ok(event)
    }

    /// Update the status of events that was previously received.
    ///
    /// This will ensure that the consumer will start from the offset after these events.
    pub async fn commit<'m>(&'m self, events: &[Event<'m>]) -> Result<(), anyhow::Error> {
        for event in events {
            self.metrics.committed_total.with_label_values(&[event.topic()]).inc();
        }
        match &self.inner {
            InnerConsumer::Kafka(consumer) => consumer.commit(events).await,
            InnerConsumer::Sqs(consumer) => consumer.commit(events).await,
        }
    }
}

#[derive(Clone, Debug, clap::Parser, Default)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct EventBusConfig {
    /// Event bus to configure
    #[arg(env = "EVENT_BUS_TYPE", long = "event-bus", value_enum, default_value = "kafka")]
    pub event_bus: EventBusType,

    /// Access key if using SQS event bus
    #[arg(env = "SQS_ACCESS_KEY", long = "sqs-access-key")]
    pub sqs_access_key: Option<String>,

    /// Secret key if using SQS event bus
    #[arg(env = "SQS_SECRET_KEY", long = "sqs-secret-key")]
    pub sqs_secret_key: Option<String>,

    /// Secret key if using SQS event bus
    #[arg(env = "SQS_REGION", long = "sqs-region")]
    pub sqs_region: Option<String>,

    /// Kafka bootstrap servers if using Kafka event bus
    #[arg(
        env = "KAFKA_BOOTSTRAP_SERVERS",
        long = "kafka-bootstrap-servers",
        default_value = "localhost:9092"
    )]
    pub kafka_bootstrap_servers: String,
}

impl EventBusConfig {
    /// Create a new event bus of a given type registered with the prometheus metrics.
    pub async fn create(&self, registry: &Registry) -> Result<EventBus, anyhow::Error> {
        match self.event_bus {
            EventBusType::Kafka => {
                let bootstrap = &self.kafka_bootstrap_servers;
                let bus = kafka::KafkaEventBus::new(bootstrap.to_string())?;
                Ok(EventBus {
                    metrics: Metrics::register(registry)?,
                    inner: InnerBus::Kafka(bus),
                })
            }
            EventBusType::Sqs => {
                let access_key = self
                    .sqs_access_key
                    .clone()
                    .ok_or(Error::MissingParameter("sqs-access-key".into()))?;
                let secret_key = self
                    .sqs_secret_key
                    .clone()
                    .ok_or(Error::MissingParameter("sqs-secret-key".into()))?;
                let region = self
                    .sqs_region
                    .clone()
                    .ok_or(Error::MissingParameter("sqs-region".into()))?;
                let bus = sqs::SqsEventBus::new(access_key, secret_key, region).await?;
                Ok(EventBus {
                    metrics: Metrics::register(registry)?,
                    inner: InnerBus::Sqs(bus),
                })
            }
        }
    }
}

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum EventBusType {
    #[clap(name = "kafka")]
    Kafka,
    #[clap(name = "sqs")]
    Sqs,
}

impl Default for EventBusType {
    fn default() -> Self {
        Self::Kafka
    }
}
