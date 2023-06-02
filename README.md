# Trustification

[![CI](https://github.com/trustification/trustification/workflows/CI/badge.svg)](https://github.com/trustification/trustification/actions?query=workflow%3A%22CI%22)
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/tag/trustification/trustification?sort=semver)](https://github.com/trustification/trustification/releases)


Trustification is a collection of software that allow you to store bill of materials (SBOM), security information (VEX) for your organization and
use that information to learn impact of vulnerabilities and dependency changes.

* [Bombastic](bombastic/README.md) - Storage and archival of SBOM documents.
* [Vexination](vexination/README.md) - Storage and archival of VEX documents.
* [Reservoir](reservoir/README.md) - Managing product metadata and access control.

## Running locally

Prerequisite: podman-compose or docker-compose.

To start all dependencies and trustification components:

``` shell
cd deploy/compose
docker-compose -f compose.yaml -f compose-trustification.yaml -f compose-guac.yaml up
```

This will start MinIO and Kafka for object storage and eventing and then run all the trustification services. It will also start to ingest data from Red Hat sources automatically via the vexination-walker and (TODO bombastic-walker) processes.

## Usage

### Searching

You can search all the data using the `spog-search` endpoint:

```shell
curl "http://localhost:8083/?q=bind"
```

## Building

To build all trustification components:

``` shell
cargo build
```

To use containers to build and package:

``` shell
podman build -t trust -f trust/Containerfile .
```
