# Developing Bombastic

## Running locally

### Storage service

The simplest way to run storage locally is to use MinIO. [Download](https://min.io/download) and run for your platform. It can run as a container or as a standalone binary. 

With the standalone binary, you can run it like this:

```
MINIO_ROOT_USER=admin MINIO_ROOT_PASSWORD=password minio server data --console-address ":9001"
```

Once running, open the [console](http://localhost:9001) and create a bucket named 'bombastic'.

## API

To run the API, you can use cargo:

```
RUST_LOG=info cargo run -p bombastic-api -- run --index index.sqlite
```

At this point, you can PUT and GET SBOMs with the API using the id.

To ingest an SBOM:

```
curl -X PUT -d@my-sbom.json http://localhost:8080/api/v1/sbom/mysbom
```

For searching using the index, more setup is required.

## Kafka

[Download Kafka](https://kafka.apache.org/downloads) and follow the [quick start](https://kafka.apache.org/quickstart) for running it.


## Indexer

The indexer requires a connection to Kafka. To run it:

```
RUST_LOG=info cargo run -p bombastic-indexer -- run --index index.sqlite
```

## Storage notificatons

In order for the indexer to know about new entries, you need to configure MinIO to forward those events to Kafka:

```

```



* Setup storage consumer
* Setup indexer
