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

use crate::{Event, EventBus, EventConsumer};

#[allow(unused)]
pub struct KafkaEventBus {
    brokers: String,
    producer: FutureProducer,
}

pub struct KafkaEvent<'m> {
    message: BorrowedMessage<'m>,
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
    type Consumer<'m> = StreamConsumer;

    async fn create(&self, topics: &[&str]) -> Result<(), anyhow::Error> {
        let admin: AdminClient<_> = ClientConfig::new().set("bootstrap.servers", &self.brokers).create()?;
        let topics: Vec<NewTopic> = topics
            .iter()
            .map(|t| NewTopic::new(t, 1, rdkafka::admin::TopicReplication::Fixed(1)))
            .collect();
        admin.create_topics(&topics[..], &AdminOptions::default()).await?;
        Ok(())
    }

    async fn subscribe(&self, group: &str, topics: &[&str]) -> Result<Self::Consumer<'_>, anyhow::Error> {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("group.id", group)
            .set("bootstrap.servers", &self.brokers)
            .set("enable.partition.eof", "false")
            .set("session.timeout.ms", "6000")
            .set("enable.auto.commit", "false")
            .create()?;
        let topics: Vec<&str> = topics.into();
        consumer.subscribe(&topics[..])?;
        Ok(consumer)
    }

    async fn send(&self, topic: &str, data: &[u8]) -> Result<(), anyhow::Error> {
        let record = FutureRecord::to(topic).payload(data);
        self.producer
            .send::<(), _, _>(record, Duration::from_secs(10))
            .await
            .map_err(|(err, _)| err)?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl EventConsumer for StreamConsumer {
    type Event<'m> = KafkaEvent<'m> where Self: 'm;
    async fn next<'m>(&'m self) -> Result<Option<Self::Event<'m>>, anyhow::Error> {
        let message = self.recv().await?;
        Ok(Some(KafkaEvent { message }))
    }

    async fn commit<'m>(&'m self, events: &[Self::Event<'m>]) -> Result<(), anyhow::Error> {
        let mut position = self.position()?;
        for event in events {
            let topic = event.message.topic();
            let partition = event.message.partition();
            let offset = event.message.offset() + 1;
            position.set_partition_offset(topic, partition, rdkafka::Offset::Offset(offset))?;
        }
        Consumer::commit(self, &position, rdkafka::consumer::CommitMode::Sync)?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl<'m> Event for KafkaEvent<'m> {
    fn payload(&self) -> Option<&[u8]> {
        self.message.payload()
    }

    fn topic(&self) -> &str {
        self.message.topic()
    }
}
