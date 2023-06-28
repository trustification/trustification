//! Event bus used in Trustification.

use prometheus::{opts, register_int_counter_vec_with_registry, IntCounterVec, Registry};

mod kafka;
mod sqs;

#[allow(clippy::large_enum_variant)]
pub enum Event<'m> {
    Kafka(kafka::KafkaEvent<'m>),
    Sqs(sqs::SqsEvent<'m>),
}

impl<'m> Event<'m> {
    pub fn payload(&self) -> Option<&[u8]> {
        match self {
            Self::Kafka(event) => event.payload(),
            Self::Sqs(event) => event.payload(),
        }
    }

    pub fn topic(&self) -> &str {
        match self {
            Self::Kafka(event) => event.topic(),
            Self::Sqs(event) => event.topic(),
        }
    }
}

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
    pub async fn create(&self, topics: &[&str]) -> Result<(), anyhow::Error> {
        match &self.inner {
            InnerBus::Kafka(bus) => bus.create(topics).await,
            InnerBus::Sqs(bus) => bus.create(topics).await,
        }
    }

    pub async fn send(&self, topic: &str, data: &[u8]) -> Result<(), anyhow::Error> {
        match &self.inner {
            InnerBus::Kafka(bus) => bus.send(topic, data).await?,
            InnerBus::Sqs(bus) => bus.send(topic, data).await?,
        }
        self.metrics.sent_total.with_label_values(&[topic]).inc();
        Ok(())
    }
}

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

#[derive(Clone, Debug, clap::Parser)]
#[command(rename_all_env = "SCREAMING_SNAKE_CASE")]
pub struct EventBusConfig {
    /// Event bus to configure
    #[arg(long = "event-bus", value_enum, default_value = "kafka")]
    pub event_bus: EventBusType,

    /// Kafka bootstrap servers if using Kafka event bus
    #[arg(long = "kafka-bootstrap-servers", default_value = "localhost:9092")]
    pub kafka_bootstrap_servers: String,
}

impl EventBusConfig {
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
                let bus = sqs::SqsEventBus::new().await?;
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
