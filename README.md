# Trustification

[![CI](https://github.com/trustification/trustification/actions/workflows/ci.yaml/badge.svg)](https://github.com/trustification/trustification/actions?query=workflow%3A%22CI%22)
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/tag/trustification/trustification?sort=semver)](https://github.com/trustification/trustification/releases)

Trustification is a collection of software that allow you to store bill of materials (SBOM), vulnerability information (VEX) for your organization and use that information to learn impact of vulnerabilities and dependency changes.

With Trustification you can:

* Store SBOM and VEX documents for your company software and their dependencies.
* Discover and learn the state of vulnerabilities related to your software.
* Explore SBOM and VEX documents using search queries.
* Share access to your SBOM and VEX information with others.

Trustification consists of a set of services you can use standalone or together:

* [Bombastic](bombastic/README.md) - Storage and archival of SBOM documents.
* [Vexination](vexination/README.md) - Storage and archival of VEX documents.
* [V11y](v11y) - Storing and lookup information about a vulnerability.
* [Collectorist](collectorist) - A process that drives polling and populating of [GUAC](https://github.com/guacsec/guac) and V11y.
* [Spog](spog) - Single Pane Of Glass API and frontend.

Services such as Bombastic and Vexination uses S3-compatible storage for storing SBOM/VEX data and a search index. The search index is used to query data using the [sikula](https://github.com/ctron/sikula) query language.

Have a look at the README file for each service for more detailed information on how they work.

## Usage

You can try out a publicly hosted trustification instance at [https://trustification.dev](https://trustification.dev). This instance is ingested with Red Hat security advisories and SBOMs for Red Hat products only.

## Running locally

Prerequisite: an implementation of the [Compose
Spec](https://www.compose-spec.io/) such as [Docker
Desktop](https://www.docker.com/products/docker-desktop/) or
[podman-compose](https://github.com/containers/podman-compose). For
the latter, v1.0.6 or higher is required.

To start all dependencies and trustification components:

For Linux systems only:

```shell
export SELINUX_VOLUME_OPTIONS=':Z'
```

``` shell
cd deploy/compose
podman-compose -f compose.yaml -f compose-trustification.yaml -f compose-guac.yaml -f compose-walkers.yaml up
```

If you'd like to run [a specific
release](https://github.com/trustification/trustification/releases),
edit [the .env file](deploy/compose/.env) in that directory and
set TRUST_VERSION to the desired release label.

This will start MinIO and Kafka for object storage and eventing and
then run all the trustification services. It will also start to ingest
data from Red Hat sources automatically. You should be able to open
the UI by pointing your browser to
[http://localhost:8084](http://localhost:8084).

You can also run all of the trustification services via a single binary named `trust` or using the container image `ghcr.io/trustification/trust`.

You can also try out the publicly hosted instance at [https://trustification.dev](https://trustification.dev).

## Running in production

There is a [helm chart](deploy/k8s/chart) that you can use to deploy all Trustification services. See [this file](deploy/trustification.dev/staging.yaml) for an example deployment that is used for the `staging.trustification.dev` environment.

The helm chart assumes that infrastructure such as Kafka/SQS and S3 is managed externally and that access credentials
are injected into secrets as specified in the chart configuration.

## Developing

See [DEVELOPMENT](DEVELOPING.md) for running the different components while developing.

## Building

To build all trustification components:

``` shell
cargo build
```

To use containers to build and package:

``` shell
podman build -t trust -f Containerfile .
```
