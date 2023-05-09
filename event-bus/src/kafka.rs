use std::time::Duration;

use rdkafka::admin::{AdminClient, AdminOptions, NewTopic};
use rdkafka::config::ClientConfig;
use rdkafka::consumer::stream_consumer::StreamConsumer;
use rdkafka::consumer::Consumer;
use rdkafka::error::KafkaError;
use rdkafka::message::BorrowedMessage;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::Message;

use crate::{Event, EventBus, EventConsumer, Topic};

#[allow(unused)]
pub struct KafkaEventBus {
    brokers: String,
    producer: FutureProducer,
}

pub struct KafkaEvent<'m> {
    message: BorrowedMessage<'m>,
    consumer: &'m StreamConsumer,
}

impl KafkaEventBus {
    pub fn new(brokers: String) -> Result<Self, KafkaError> {
        let producer: FutureProducer = ClientConfig::new()
            .set("message.timeout.ms", "5000")
            .set("bootstrap.servers", &brokers)
            .create()?;
        Ok(Self { brokers, producer })
    }
}

#[async_trait::async_trait]
impl EventBus for KafkaEventBus {
    type Error = KafkaError;
    type Consumer = StreamConsumer;

    async fn create(&self, topics: &[Topic]) -> Result<(), Self::Error> {
        let admin: AdminClient<_> = ClientConfig::new().set("bootstrap.servers", &self.brokers).create()?;
        let topics: Vec<NewTopic> = topics
            .iter()
            .map(|t| NewTopic::new(t.as_ref(), 1, rdkafka::admin::TopicReplication::Fixed(1)))
            .collect();
        admin.create_topics(&topics[..], &AdminOptions::default()).await?;
        Ok(())
    }

    fn subscribe(&self, group: &str, topics: &[Topic]) -> Result<Self::Consumer, Self::Error> {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("group.id", group)
            .set("bootstrap.servers", &self.brokers)
            .set("enable.partition.eof", "false")
            .set("session.timeout.ms", "6000")
            .set("enable.auto.commit", "false")
            .create()?;
        let topics: Vec<&str> = topics.iter().map(|t| t.as_ref()).collect();
        consumer.subscribe(&topics[..])?;
        Ok(consumer)
    }

    async fn send(&self, topic: Topic, data: &[u8]) -> Result<(), Self::Error> {
        let record = FutureRecord::to(topic.as_ref()).payload(data);
        self.producer
            .send::<(), _, _>(record, Duration::from_secs(10))
            .await
            .map_err(|(err, _)| err)?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl EventConsumer for StreamConsumer {
    type Error = KafkaError;
    type Event<'m> = KafkaEvent<'m> where Self: 'm;
    async fn next<'m>(&'m self) -> Result<Self::Event<'m>, Self::Error> {
        let message = self.recv().await?;
        Ok(KafkaEvent {
            message,
            consumer: &self,
        })
    }
}

impl<'m> Event for KafkaEvent<'m> {
    type Error = KafkaError;
    fn payload(&self) -> Option<&[u8]> {
        self.message.payload()
    }

    fn topic(&self) -> Result<Topic, ()> {
        self.message.topic().try_into()
    }

    fn commit(&self) -> Result<(), Self::Error> {
        self.consumer
            .commit_message(&self.message, rdkafka::consumer::CommitMode::Sync)?;
        Ok(())
    }
}
