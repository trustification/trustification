# Integration tests

By default, these tests expect the services defined in the
[default compose script](../deploy/compose/compose.yaml) 
and [Guac compose script](../deploy/compose/compose-guac.yaml) 
-- MinIO, Kafka, and Keycloak -- to be up and running.
Once they're ready, run the tests like so:

```shell
cargo test -p integration-tests
```

To see more detailed output:

```shell
RUST_LOG=info cargo test -p integration-tests -- --nocapture
```

The tests do not require Trustification itself to be running. Each
test will start whatever services it requires and then shut them down
when the test completes. It is possible, however, to override that
default behavior and direct the integration tests at a particular
Trustification instance.

## Testing a remote Trustification instance

Setting the `TRUST_URL` environment variable to the URL for a remote
trustification server triggers the integs to be run against it.

If it's set, other env vars will be required:
  * `TRUST_ID` -- a client id with *manager* authorization, i.e. "write" permissions
  * `TRUST_SECRET` -- the secret associated with `TRUST_ID`
  * `TRUST_USER_ID` -- (optional, defaults to `TRUST_ID`) a client id
    for a non-privileged user, i.e. "read-only"
  * `TRUST_USER_SECRET` -- (optional, defaults to `TRUST_SECRET`) the
    secret associated with `TRUST_USER_ID`
  * `KAFKA_BOOTSTRAP_SERVERS` -- (optional) if set, its value will be
    used to configure the event bus required by some of the
    tests. Otherwise, [SQS](https://aws.amazon.com/sqs/) is assumed
    and valid AWS credentials will be required.

Some examples might be nice. Let's assume you're running a local
instance of trustification like so:

```shell
docker compose -f deploy/compose/compose-trustification.yaml up
```

The default URL for that instance is http://localhost:8084 so we'll
point the integs there. We first need to set `KAFKA_BOOTSTRAP_SERVERS`
for those tests that expect events.

```shell
export KAFKA_BOOTSTRAP_SERVERS=localhost:9092
```

To run all the tests:

```shell
TRUST_URL=http://localhost:8084 \
TRUST_ID=testing-manager \
TRUST_USER_ID=testing-user \
TRUST_SECRET=R8A6KFeyxJsMDBhjfHbpZTIF0GWt43HP \
cargo test -p integration-tests 
```

Note that our testing client id's share the same secret, so we can
omit the `TRUST_USER_SECRET` variable.  Not all variables are required
by each test, so if you limit which tests run, you can omit others. In
fact, only a few tests require a `TRUST_USER_ID` at all.

These would be enough to run, say...

```shell
export TRUST_URL=http://localhost:8084
export TRUST_ID=testing-manager
export TRUST_SECRET=R8A6KFeyxJsMDBhjfHbpZTIF0GWt43HP
```

...just the `bombastic_search` test...

```shell
cargo test -p integration-tests bombastic_search
```

...or perhaps just the spog tests:

```shell
cargo test -p integration-tests --test spog
```
