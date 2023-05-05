# Developing Bombastic

## Running locally

### Storage service

The simplest way to run storage locally is to use MinIO. [Download](https://min.io/download) and run for your platform. It can run as a container or as a standalone binary. 

With the standalone binary, you can run it like this:

```
MINIO_ROOT_USER=admin MINIO_ROOT_PASSWORD=password MINIO_NOTIFY_KAFKA_ENABLE_EVENTBUS="on" MINIO_NOTIFY_KAFKA_BROKERS_EVENTBUS="localhost:9092" MINIO_NOTIFY_KAFKA_TOPIC_EVENTBUS="stored" minio server data --console-address ":9001"
```

Once running, open the [console](http://localhost:9001) and create a bucket named 'bombastic'.

## API

To run the API, you can use cargo:

```
RUST_LOG=info cargo run -p bombastic-api -- run --index api-index.sqlite
```

At this point, you can PUT and GET SBOMs with the API using the id.

To ingest an SBOM:

```
curl -X PUT -d@my-sbom.json http://localhost:8080/api/v1/sbom/mysbom
```

For searching using the index, more setup is required.

## Kafka

[Download Kafka](https://kafka.apache.org/downloads) and follow the [quick start](https://kafka.apache.org/quickstart) for running it.

Once started, create three topics: `stored`, `indexed`, `failed`


## Indexer

The indexer requires a connection to Kafka. To run it:

```
RUST_LOG=info cargo run -p bombastic-indexer -- run --index indexer-index.sqlite
```

At this point you should be able to ingest and query the data, either directly or indirectly using the index:

```
curl -X GET http://localhost:8080/api/v1/sbom/mysbom
curl -X GET http://localhost:8080/api/v1/sbom?purl=pkg%3Amaven%2Fio.seedwing%2Fseedwing-java-example%401.0.0-SNAPSHOT%3Ftype%3Djar
```

The indexer will automatically sync the index to the S3 bucket, while the API will periodically retrieve the index from S3. Therefore, there may be a delay between storing the entry and it being indexed.

## Exporter

TODO
