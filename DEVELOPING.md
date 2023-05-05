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

For searching using the index, more setup is required.

## TODO

* Setup storage consumer
* Setup indexer
