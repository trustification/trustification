# billbo

*WIP* This is all just thoughts and ideas at this point

![Bilbo](bilbo.jpg)

Billbo is a storage and archival service for Software Bill of Material (SBOM) files, from now on called SBOMs in plural instead of SBsOM.

Why would you use Billbo? If you're a big organization, you have a lot of SBOMs, possibly terrabytes of SBOM data. You have some parts of your organization that produces SBOMs, and you need to store them somewhere safe. Amazon S3 or similar is probably one of the safer options around since it's API is ubiquitous when you look for object storage.

But if you're a big organization, you may need to provide these SBOMs to consumers from time to time, either to internal users or customers, fast. And if you're fancy, maybe you even have some need to automatically stream new SBOMs to external systems.

Oh, and authentication! You definitely want that, at least for producers.

Billbo consists of:

* An API for publishing and consuming SBOM data
* Keycloak or similar (OIDC) for authentication and authorization.
* A lookup index based on SQLite. 
* Amazon S3 or similar object storage such Ceph or MinIO. This way you can run it locally with MinIO, on company infra with Ceph, or on AWS with S3.
* Apache Kafka or similar for eventing, everybody loves Kafka.

### "Why would I need all that, it's just files lol?"

You're probably not a big organization, please continue to use files.

### "I but you need 100 gazillion cores to run that system"

It's written in Rust so it must be fast. 

## Crates 

Billbo consists of the following Rust crates, of which some are common APIs and others are standalone micro-services.

* `billbo-storage` - facade to s3 api used by indexer and api
* `billbo-api` - API server
* `billbo-indexer` - Indexing process consuming events from event-bus and indexing into sqlite
* `billbo-index` - API for accessing index
* `billbo-exporter` - Exporter process consuming events from event-bus and exporting data
* `billbo-event-bus` - API for consuming from event bus (and publishing)

