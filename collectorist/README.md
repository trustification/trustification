# A Vertical Slice 

## GUAC

In some window, run GUAC according to the upstream GUAC instructions:

    docker compose up --force-recreate

Leave that process running.

## Collectorist

The Collectorist drives the polling and populating of GUAC.
Run a single instance of the Collectorist as we do, using the `trust` CLI after building this repository.

    RUST_LOG=info ./target/debug/trust collectorist api

## OSV Collector

The OSV collector is driven by the Collectorist. 
It must be run with the collectorist URL specified, which defaults to the correct URL unless you're getting weird.

    RUST_LOG=info ./target/debug/trust collectorist api

# What's going on?

The Collectorist connects to GUAC's gRPC end-point, and polls for newly-added-purls.
Any Collector (such as the OSV collector) which connects to the Collectorist will:

* Get notified of the GUAC GraphQL endpoint
* Get notified as new pURLs are discovered
* Get notified when old pURLs need a re-scan

Upon notification (called a "gather request"), each Collector will do whatever it can, and if it notices something worthwhile, shall ingest it into GUAC.
Additionally, it returns a list of notable pURLs it noticed. 
If for instance it receives a gather request for 20 pURLs, and 19 are non-notable, it will only return an array containing the single pURL that had a notable vulnerability.

# What needs to go on?

Similar codepath should be invoked when an external party (such as CRDA) wants to know, for certain, everything knowablw about a given set of pURLs.
CRDA asks Exhort, which asks the Collectorist, which asks each collector, and *only returns and unwinds* when all collectors have completed their ingestioning.
Then... exhort can ask GUAC everything it should pass back to CRDA.

Turtles upon turtles.