# Event-bus

A crate for accessing an event bus or message queue backed by either Apache Kafka or AWS (Amazon Web Services) SQS (Simple Queue Service).

Although it supports creating queues and topic, the intended use of that feature is for local testing. In general,
it is assumed that topics and queues are created before consuming or producing events.

NOTE: SQS is not a pub-sub system, and so multiple subscribers to the same SQS queue will distribute messages among the subscribers. For setting up a pub-sub with AWS, use the Simple Notification Service (SNS) and multiple SQS queues subscribing to an SNS topic.
