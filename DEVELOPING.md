# Developing Bombastic

## Running locally

Requires podman-compose.

```
podman-compose -f compose.yaml up
```

This will start MinIO and Kafka in containers and initialize them accordingly so that you don't need to configure anything. Default arguments of Bombastic components will work with this setup.

## API

To run the API, you can use cargo:

```
RUST_LOG=info cargo run -p bombastic-api -- run --index api-index.sqlite --devmode
```

For searching using the index, more setup is required.

## Indexer

The indexer consumes events from Kafka and indexes SBOM entries:

```
RUST_LOG=info cargo run -p bombastic-indexer -- run --index indexer-index.sqlite --devmode
```

At this point, you can PUT and GET SBOMs with the API using the id. To ingest an SBOM:

```
curl -X PUT -d@my-sbom.json http://localhost:8080/api/v1/sbom/mysbom
```

To query the data, either using direct lookup or querying via the index:

```
curl -X GET http://localhost:8080/api/v1/sbom/mysbom
curl -X GET http://localhost:8080/api/v1/sbom?purl=pkg%3Amaven%2Fio.seedwing%2Fseedwing-java-example%401.0.0-SNAPSHOT%3Ftype%3Djar
```

The indexer will automatically sync the index to the S3 bucket, while the API will periodically retrieve the index from S3. Therefore, there may be a delay between storing the entry and it being indexed.

## Exporter

TODO
