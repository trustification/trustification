# RH prodesec SPDX crawler

## Usage

```shell
RUST_LOG=info cargo run --bin trust bombastic walker  --bombastic-url localhost:8082
```

By default, it will get files listed [here](https://access.redhat.com/security/data/sbom/beta/changes.csv).

## Options

Override the changes.csv location :  `--changes-url https://access.redhat.com/security/data/sbom/beta/changes.csv`

Start in long-running mode, to monitor the change file and update when needed: `--scan-interval 30s`

Provide the path to the scripts: `--scripts_path bombastic/walker`

Set a custom working directory : `--workdir /tmp/walker`

Settings can be set with environment variables.
