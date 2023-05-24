# Developing Vexination

## Running locally

Requires `podman-compose`.

```shell
podman-compose -f compose.yaml up
```

This will start MinIO and Kafka in containers and initialize them accordingly so that you don't need to configure anything. Default arguments of Vexination components will work with this setup.

## API

To run the API, you can use cargo:

```shell
RUST_LOG=info cargo run -p vexination-api -- run --devmode
```

At this point, you can POST and GET VEX documents with the API using the id. To ingest a VEX document:

```shell
curl -X POST --json @testdata/rhsa-2023_1441.json http://localhost:8080/api/v1/vex
```

To query the data, either using direct lookup or querying via the index using the advisory:

```shell
curl -X GET http://localhost:8080/api/v1/vex?advisory=RHSA-2023:1441
```

You can also crawl Red Hat security data using the walker, which will feed the S3 storage with data:


```shell
RUST_LOG=info cargo run -p vexination-walker -- run --devmode --source https://www.redhat.com/.well-known/csaf/provider-metadata.json -3
```
