use rdkafka::config::ClientConfig;
use rdkafka::consumer::stream_consumer::StreamConsumer;
use rdkafka::consumer::Consumer;
use rdkafka::error::KafkaError;
use rdkafka::message::BorrowedMessage;
use rdkafka::producer::FutureProducer;
use rdkafka::Message;

use crate::{Event, EventBus};

#[allow(unused)]
pub struct KafkaEventBus {
    consumer: StreamConsumer,
    producer: FutureProducer,
    indexed_topic: String,
    failed_topic: String,
}
pub struct KafkaEvent<'m> {
    message: BorrowedMessage<'m>,
    consumer: &'m StreamConsumer,
}

impl KafkaEventBus {
    pub fn new(
        brokers: String,
        group_id: String,
        stored_topic: String,
        indexed_topic: String,
        failed_topic: String,
    ) -> Result<Self, anyhow::Error> {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("group.id", &group_id)
            .set("bootstrap.servers", &brokers)
            .set("enable.partition.eof", "false")
            .set("session.timeout.ms", "6000")
            .set("enable.auto.commit", "false")
            .create()?;

        consumer.subscribe(&[&stored_topic])?;

        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", &brokers)
            .set("message.timeout.ms", "5000")
            .create()?;

        Ok(Self {
            consumer,
            producer,
            indexed_topic,
            failed_topic,
        })
    }
}

impl EventBus for KafkaEventBus {
    type Error = KafkaError;
    type Event<'m> = KafkaEvent<'m>;
    async fn poll<'m>(&'m self) -> Result<Self::Event<'m>, Self::Error> {
        let message = self.consumer.recv().await?;
        Ok(KafkaEvent {
            message,
            consumer: &self.consumer,
        })
    }
}

impl<'m> Event for KafkaEvent<'m> {
    type Error = KafkaError;
    fn payload(&self) -> Option<&[u8]> {
        self.message.payload()
    }

    fn commit(&self) -> Result<(), Self::Error> {
        self.consumer
            .commit_message(&self.message, rdkafka::consumer::CommitMode::Sync)?;
        Ok(())
    }
}
