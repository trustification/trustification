use aws_config::meta::region::RegionProviderChain;
use aws_sdk_sqs::{
    config::Region, operation::receive_message::ReceiveMessageOutput, types::Message, Client, Error as SqsSdkError,
};
use thiserror::Error;

use crate::Event;

#[derive(Debug, Error)]
pub enum SqsError {
    #[error("Error from SQS: {0}")]
    Sqs(SqsSdkError),
}

impl From<SqsSdkError> for SqsError {
    fn from(e: SqsSdkError) -> Self {
        Self::Sqs(e)
    }
}

#[allow(unused)]
pub struct SqsEventBus {
    client: Client,
}

impl SqsEventBus {
    pub(crate) async fn new() -> Result<Self, anyhow::Error> {
        let region_provider = RegionProviderChain::default_provider().or_else(Region::new("eu-west-1"));
        let config = aws_config::from_env().region(region_provider).load().await;
        let client = Client::new(&config);
        Ok(Self { client })
    }
}

impl SqsEventBus {
    pub(crate) async fn create(&self, topics: &[&str]) -> Result<(), anyhow::Error> {
        for topic in topics.iter() {
            self.client.create_queue().queue_name(topic.to_string()).send().await?;
        }
        Ok(())
    }

    pub(crate) async fn subscribe(&self, _group: &str, topics: &[&str]) -> Result<SqsConsumer, anyhow::Error> {
        Ok(SqsConsumer {
            client: &self.client,
            queues: topics.iter().map(|s| s.to_string()).collect(),
        })
    }

    pub(crate) async fn send(&self, topic: &str, data: &[u8]) -> Result<(), anyhow::Error> {
        let s = core::str::from_utf8(data).unwrap();
        self.client
            .send_message()
            .queue_url(topic)
            .message_body(s)
            .send()
            .await?;
        Ok(())
    }
}

pub struct SqsConsumer<'m> {
    client: &'m Client,
    queues: Vec<String>,
}

impl<'d> SqsConsumer<'d> {
    pub(crate) async fn next<'m>(&'m self) -> Result<Option<SqsEvent<'m>>, anyhow::Error> {
        let queue_futs: Vec<_> = self
            .queues
            .iter()
            .map(|q| {
                Box::pin(
                    self.client
                        .receive_message()
                        .set_wait_time_seconds(Some(20))
                        .set_max_number_of_messages(Some(1))
                        .queue_url(q.as_str())
                        .send(),
                )
            })
            .collect();

        let (result, idx, _) = futures::future::select_all(queue_futs).await;
        let topic = &self.queues[idx];
        let message: ReceiveMessageOutput = result?;
        if let Some(messages) = message.messages() {
            if let Some(message) = messages.first() {
                return Ok(Some(SqsEvent {
                    queue: topic.as_str(),
                    message: message.clone(),
                }));
            }
        }
        Ok(None)
    }

    pub(crate) async fn commit<'m>(&'m self, events: &[Event<'m>]) -> Result<(), anyhow::Error> {
        for event in events {
            if let Event::Sqs(event) = event {
                self.client
                    .delete_message()
                    .queue_url(event.queue)
                    .set_receipt_handle(event.message.receipt_handle().map(|s| s.into()))
                    .send()
                    .await?;
            }
        }
        Ok(())
    }
}

pub struct SqsEvent<'m> {
    queue: &'m str,
    message: Message,
}

impl<'m> SqsEvent<'m> {
    pub(crate) fn topic(&self) -> &str {
        self.queue
    }

    pub(crate) fn payload(&self) -> Option<&[u8]> {
        self.message.body().map(|m| m.as_bytes())
    }
}
