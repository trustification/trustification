# Developing Trustification

This document describes how to run all of the trustification processes for local development. You can skip running some of the
processes if you don't need them for developing.

For creating new services in trustification, see [NEWSERVICE.md](NEWSERVICE.md).

## Dependencies

### docker-compose

Requires `docker-compose` to run dependent services.

For Linux systems only:
``` shell
$ export SELINUX_VOLUME_OPTIONS=':Z'
```

```shell
cd deploy/compose
docker-compose -f compose.yaml -f compose-guac.yaml up
```

This will start MinIO and Kafka in containers and initialize them accordingly so that you don't need to configure anything. Default arguments of Vexination components will work with this setup.

The MinIO console is available at http://localhost:9001

### protobuf-compiler

On Fedora, try:

```shell
sudo dnf install protobuf-compiler
```

On OSX, try:

```shell
brew install protobuf
```

## Integration tests

Trustification comes with a set of [integration
tests](./integration-tests/) that you can run after the required
services defined in the [default compose
script](./deploy/compose/compose.yaml) 
and [Guac compose script](./deploy/compose/compose-guac.yaml) are up and running. 
Once they're up, run the tests like so:

```shell
cargo test -p integration-tests
```

To see more detailed output:

```shell
RUST_LOG=info cargo test -p integration-tests -- --nocapture
```

## Single sign on

The default credentials for single sign on are:

* **Username:** `admin`
* **Password:** `admin123456`

When running with `--devmode` and authentication enabled, you can request an access token using:

```shell
curl -s -d "client_id=walker" -d "client_secret=ZVzq9AMOVUdMY1lSohpx1jI3aW56QDPS" -d 'grant_type=client_credentials' \
  'http://localhost:8090/realms/chicken/protocol/openid-connect/token' | jq -r .access_token
```

You can set an environment variable for passing to `curl` like this (just be sure to request a fresh token when it
expired):

```shell
TOKEN=$(curl -s -d "client_id=walker" -d "client_secret=ZVzq9AMOVUdMY1lSohpx1jI3aW56QDPS" -d 'grant_type=client_credentials' \
  'http://localhost:8090/realms/chicken/protocol/openid-connect/token' | jq -r .access_token)
CURL_OPTS="--oauth2-bearer $TOKEN"
echo "Access Token: $TOKEN"
```

Or when using `fish`:

```shell
set TOKEN $(curl -s -d "client_id=walker" -d "client_secret=ZVzq9AMOVUdMY1lSohpx1jI3aW56QDPS" -d 'grant_type=client_credentials' \
  'http://localhost:8090/realms/chicken/protocol/openid-connect/token' | jq -r .access_token)
```

You can then add `$CURL_OPTS` to all `curl` calls in order to use the token.

## API keys

Some of the collectors require additional API keys. They can be configured through environment variables. As they are
environment variables and shouldn't change frequently, it is possible to set them in some initialization script like
`.bashrc`.

> [!NOTE]
> Be sure to set those API keys before starting the following services.

### NVD

For the `collector-nvd` service, you will need:

```shell
export NVD_API_KEY=<your-api-key>
```

You can request one [here](https://nvd.nist.gov/developers/request-an-api-key).

### Snyk

For the `collector-snyk` service, you will need:

```shell
export SNYK_TOKEN=<your-api-token>
export SNYK_ORG_ID=<the-matching-org-id>
```

You can request one [here](https://docs.snyk.io/enterprise-setup/snyk-broker/snyk-broker-code-agent/setting-up-the-code-agent-broker-client-deployment/step-1-obtaining-the-required-tokens-for-the-setup-procedure/obtaining-your-snyk-api-token).

## APIs

To run the API processes, you can use cargo:

```shell
RUST_LOG=info cargo run -p trust -- vexination api --devmode &
RUST_LOG=info cargo run -p trust -- bombastic api --devmode &
RUST_LOG=info cargo run -p trust -- spog api --devmode  &
RUST_LOG=info cargo run -p trust -- v11y api --devmode &
RUST_LOG=info cargo run -p trust -- collectorist api --devmode &
RUST_LOG=info cargo run -p trust -- collector osv --devmode &
RUST_LOG=info cargo run -p trust -- collector nvd --devmode &
RUST_LOG=info cargo run -p trust -- collector snyk --devmode &
```

If you want to disable authentication (not recommended unless you are not exposing any services outside localhost), you can pass the `--authentication-disabled` flag to the above commands.

## Indexing

To run the indexer processes, you can use cargo:

```shell
RUST_LOG=info cargo run -p trust -- vexination indexer --devmode &
RUST_LOG=info cargo run -p trust -- bombastic indexer --devmode &
```

## Ingesting VEX

**NOTE:** If authentication is enabled, which is the default, you will need to provide an access token. See [above](#single-sign-on).

At this point, you can POST and GET VEX documents with the API using the id. To ingest a VEX document:

```shell
curl -X POST --json @vexination/testdata/rhsa-2023_1441.json http://localhost:8081/api/v1/vex
```

To get the data, either using direct lookup:

```shell
curl -X GET "http://localhost:8081/api/v1/vex?advisory=RHSA-2023:1441"
```

You can also crawl Red Hat security data using the walker, which will feed the S3 storage with data:

```shell
RUST_LOG=info cargo run -p trust -- vexination walker --devmode --source https://www.redhat.com/.well-known/csaf/provider-metadata.json -3
```

If you have a local copy of the data, you can also run:

```shell
RUST_LOG=info cargo run -p trust -- vexination walker --devmode -3 --sink http://localhost:8081 --source file:///path/to/copy
```

## Ingesting SBOMs

At this point, you can POST and GET SBOMs with the API using a unique identifier for the id. To ingest a small-ish SBOM:

**NOTE:** If authentication is enabled, which is the default, you will need to provide an access token. See [above](#single-sign-on).

```shell
curl --json @bombastic/testdata/my-sbom.json http://localhost:8082/api/v1/sbom?id=my-sbom
```
For large SBOM's, you may use a "chunked" `Transfer-Encoding`:
```shell
curl -H "transfer-encoding: chunked" --json @bombastic/testdata/ubi9-sbom.json http://localhost:8082/api/v1/sbom?id=ubi9
```
You can also post compressed SBOM's using the `Content-Encoding` header, though the `Content-Type` header
should always be `application/json` (as is implied by the `--json` option above).

Both `zstd` and `bzip2` encodings are supported:
```shell
curl -H "transfer-encoding: chunked" \
     -H "content-encoding: bzip2" \
     -H "content-type: application/json" \
     -T openshift-4.13.json.bz2 \
     http://localhost:8082/api/v1/sbom?id=openshift-4.13
```
You can also crawl Red Hat security data using the walker, which will push data through bombastic:

```shell
RUST_LOG=info cargo run -p trust bombastic walker --bombastic-url http://localhost:8082
```

Assuming you have the system set up using `--devmode`, you can use the following command to run the walker with
a matching OIDC client configuration:

```shell
RUST_LOG=info cargo run -p trust bombastic walker --bombastic-url http://localhost:8082 --devmode
```

Example for importing an SBOM generated by `syft`:

```shell
REGISTRY=registry.k8s.io/coredns
IMAGE=coredns
TAG=v1.9.3

podman pull $REGISTRY/$IMAGE:$TAG
DIGEST=$(podman images $REGISTRY/$IMAGE:$TAG --digests '--format={{.Id}}')
PURL=pkg:oci/$IMAGE@sha256:$DIGEST
syft -q -o spdx-json --name $IMAGE $REGISTRY/$IMAGE:$TAG | http --json POST http://localhost:8082/api/v1/sbom purl==$PURL sha256==$DIGEST
```

Or when pulling by digest:

```shell
REGISTRY=docker.io/bitnami
IMAGE=postgresql
DIGEST=e6d322cf36ff6b5e2bb13d71c816dc60f1565ff093cc220064dba08c4b057275

PURL=pkg:oci/$IMAGE@sha256:$DIGEST
syft -q -o spdx-json --name $IMAGE $REGISTRY/$IMAGE@sha256:$DIGEST | http --json POST http://localhost:8082/api/v1/sbom purl==$PURL sha256==$DIGEST
```

To query the data, either using direct lookup or querying via the index using the sha256 digest:

```shell
curl "http://localhost:8082/api/v1/sbom?id=pkg%3Amaven%2Fio.seedwing%2Fseedwing-java-example%401.0.0-SNAPSHOT%3Ftype%3Djar"
curl -o ubi9-sbom.json "http://localhost:8082/api/v1/sbom?id=ubi9"
```

The indexer will automatically sync the index to the S3 bucket, while the API will periodically retrieve the index from S3. Therefore, there may be a delay between storing the entry and it being indexed.

## Searching

You can search all the data using the `bombastic-api` or `vexination-api` endpoints:

```shell
curl "http://localhost:8082/api/v1/sbom/search?q=openssl"
curl "http://localhost:8081/api/v1/vex/search?q=openssl"
```

## Working with local images

If you need to build an image locally, you can do that by running

```shell
docker build -f trust/Containerfile -t trust:latest .
```

Then, you can use it like

```shell
TRUST_IMAGE=trust TRUST_VERSION=latest docker-compose -f compose.yaml -f compose-guac.yaml -f compose-trustification.yaml -f compose-collectors.yaml up --force-recreate
```
