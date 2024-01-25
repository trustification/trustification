use std::time::Duration;

use crate::Error;
use crate::Event;
use rdkafka::{
    admin::{AdminClient, AdminOptions, NewTopic},
    config::ClientConfig,
    consumer::{stream_consumer::StreamConsumer, Consumer},
    error::KafkaError,
    message::BorrowedMessage,
    producer::{FutureProducer, FutureRecord},
    Message,
};

#[allow(unused)]
pub struct KafkaEventBus {
    config: ClientConfig,
    producer: FutureProducer,
}

impl From<KafkaError> for Error {
    fn from(e: KafkaError) -> Self {
        match e {
            KafkaError::Subscription(_) => Self::Critical(e.to_string()),
            _ => Self::Transient(e.to_string()),
        }
    }
}

impl KafkaEventBus {
    pub(crate) fn new(brokers: String, properties: Vec<(String, String)>) -> Result<Self, Error> {
        let mut config = ClientConfig::new();
        config
            .set("message.timeout.ms", "5000")
            .set("bootstrap.servers", &brokers);

        for (key, value) in properties {
            config.set(key, value);
        }

        let producer: FutureProducer = config.create()?;
        Ok(Self { config, producer })
    }

    pub(crate) async fn create(&self, topics: &[&str]) -> Result<(), Error> {
        let admin: AdminClient<_> = self.config.create()?;
        let topics: Vec<NewTopic> = topics
            .iter()
            .map(|t| NewTopic::new(t, 1, rdkafka::admin::TopicReplication::Fixed(1)))
            .collect();
        admin.create_topics(&topics[..], &AdminOptions::default()).await?;
        Ok(())
    }

    pub(crate) async fn subscribe(&self, group: &str, topics: &[&str]) -> Result<KafkaConsumer, Error> {
        let mut config = self.config.clone();
        config
            .set("group.id", group)
            .set("enable.partition.eof", "false")
            .set("session.timeout.ms", "6000")
            .set("enable.auto.commit", "false")
            .set("auto.offset.reset", "earliest");

        let consumer: StreamConsumer = config.create()?;
        let topics: Vec<&str> = topics.into();
        consumer.subscribe(&topics[..])?;
        Ok(KafkaConsumer { consumer })
    }

    pub(crate) async fn send(&self, topic: &str, data: &[u8]) -> Result<(), Error> {
        let record = FutureRecord::to(topic).payload(data);
        self.producer
            .send::<(), _, _>(record, Duration::from_secs(10))
            .await
            .map_err(|(err, _)| err)?;
        Ok(())
    }
}

pub struct KafkaConsumer {
    consumer: StreamConsumer,
}

impl KafkaConsumer {
    pub(crate) async fn next(&self) -> Result<Option<KafkaEvent>, Error> {
        let message = self.consumer.recv().await?;
        Ok(Some(KafkaEvent { message }))
    }

    pub(crate) async fn commit<'m>(&'m self, events: &[Event<'m>]) -> Result<(), Error> {
        let mut position = self.consumer.position()?;
        for event in events {
            if let Event::Kafka(event) = event {
                let topic = event.message.topic();
                let partition = event.message.partition();
                let offset = event.message.offset() + 1;
                position.set_partition_offset(topic, partition, rdkafka::Offset::Offset(offset))?;
            }
        }
        Consumer::commit(&self.consumer, &position, rdkafka::consumer::CommitMode::Sync)?;
        Ok(())
    }
}

pub struct KafkaEvent<'m> {
    message: BorrowedMessage<'m>,
}

impl<'m> KafkaEvent<'m> {
    pub(crate) fn topic(&self) -> &str {
        self.message.topic()
    }

    pub(crate) fn payload(&self) -> Option<&[u8]> {
        self.message.payload()
    }
}
