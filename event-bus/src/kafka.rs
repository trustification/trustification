use std::time::Duration;

use rdkafka::{
    admin::{AdminClient, AdminOptions, NewTopic},
    config::ClientConfig,
    consumer::{stream_consumer::StreamConsumer, Consumer},
    error::KafkaError,
    message::BorrowedMessage,
    producer::{FutureProducer, FutureRecord},
    Message,
};

use crate::Event;

#[allow(unused)]
pub struct KafkaEventBus {
    brokers: String,
    producer: FutureProducer,
}

impl KafkaEventBus {
    pub(crate) fn new(brokers: String) -> Result<Self, KafkaError> {
        let producer: FutureProducer = ClientConfig::new()
            .set("message.timeout.ms", "5000")
            .set("bootstrap.servers", &brokers)
            .create()?;
        Ok(Self { brokers, producer })
    }

    pub(crate) async fn create(&self, topics: &[&str]) -> Result<(), anyhow::Error> {
        let admin: AdminClient<_> = ClientConfig::new().set("bootstrap.servers", &self.brokers).create()?;
        let topics: Vec<NewTopic> = topics
            .iter()
            .map(|t| NewTopic::new(t, 1, rdkafka::admin::TopicReplication::Fixed(1)))
            .collect();
        admin.create_topics(&topics[..], &AdminOptions::default()).await?;
        Ok(())
    }

    pub(crate) async fn subscribe(&self, group: &str, topics: &[&str]) -> Result<KafkaConsumer, anyhow::Error> {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("group.id", group)
            .set("bootstrap.servers", &self.brokers)
            .set("enable.partition.eof", "false")
            .set("session.timeout.ms", "6000")
            .set("enable.auto.commit", "false")
            .create()?;
        let topics: Vec<&str> = topics.into();
        consumer.subscribe(&topics[..])?;
        Ok(KafkaConsumer { consumer })
    }

    pub(crate) async fn send(&self, topic: &str, data: &[u8]) -> Result<(), anyhow::Error> {
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
    pub(crate) async fn next<'m>(&'m self) -> Result<Option<KafkaEvent<'m>>, anyhow::Error> {
        let message = self.consumer.recv().await?;
        Ok(Some(KafkaEvent { message }))
    }

    pub(crate) async fn commit<'m>(&'m self, events: &[Event<'m>]) -> Result<(), anyhow::Error> {
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
    pub(crate) fn payload(&self) -> Option<&[u8]> {
        self.message.payload()
    }
}
