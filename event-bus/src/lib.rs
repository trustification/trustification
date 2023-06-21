//! Traits with required functionality for the event bus used in Trustification.

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
}

pub enum EventBus {
    Kafka(kafka::KafkaEventBus),
    Sqs(sqs::SqsEventBus),
}

impl EventBus {
    pub async fn subscribe(&self, group: &str, topics: &[&str]) -> Result<EventConsumer<'_>, anyhow::Error> {
        match self {
            Self::Kafka(bus) => {
                let consumer = bus.subscribe(group, topics).await?;
                Ok(EventConsumer::Kafka(consumer))
            }
            Self::Sqs(bus) => {
                let consumer = bus.subscribe(group, topics).await?;
                Ok(EventConsumer::Sqs(consumer))
            }
        }
    }
    pub async fn create(&self, topics: &[&str]) -> Result<(), anyhow::Error> {
        match self {
            Self::Kafka(bus) => bus.create(topics).await,
            Self::Sqs(bus) => bus.create(topics).await,
        }
    }

    pub async fn send(&self, topic: &str, data: &[u8]) -> Result<(), anyhow::Error> {
        match self {
            Self::Kafka(bus) => bus.send(topic, data).await,
            Self::Sqs(bus) => bus.send(topic, data).await,
        }
    }
}

pub enum EventConsumer<'d> {
    Kafka(kafka::KafkaConsumer),
    Sqs(sqs::SqsConsumer<'d>),
}

impl<'d> EventConsumer<'d> {
    pub async fn next<'m>(&'m self) -> Result<Option<Event<'m>>, anyhow::Error> {
        match self {
            Self::Kafka(consumer) => {
                let event = consumer.next().await?;
                Ok(event.map(Event::Kafka))
            }
            Self::Sqs(consumer) => {
                let event = consumer.next().await?;
                Ok(event.map(Event::Sqs))
            }
        }
    }

    pub async fn commit<'m>(&'m self, events: &[Event<'m>]) -> Result<(), anyhow::Error> {
        match self {
            Self::Kafka(consumer) => consumer.commit(events).await,
            Self::Sqs(consumer) => consumer.commit(events).await,
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
    pub async fn create(&self) -> Result<EventBus, anyhow::Error> {
        match self.event_bus {
            EventBusType::Kafka => {
                let bootstrap = &self.kafka_bootstrap_servers;
                let bus = kafka::KafkaEventBus::new(bootstrap.to_string())?;
                Ok(EventBus::Kafka(bus))
            }
            EventBusType::Sqs => {
                let bus = sqs::SqsEventBus::new().await?;
                Ok(EventBus::Sqs(bus))
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
