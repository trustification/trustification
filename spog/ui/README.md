# Chicken coop

## Setting up

### Toolchain

[Install Rust](https://www.rust-lang.org/tools/install), then:

```shell
rustup target add wasm32-unknown-unknown
cargo install trunk-ng
cargo binstall trunk-ng # if you have `cargo-binstall` installed
```

> [!NOTE]
> `trunk-ng` is a fork of `trunk`. Both should work at the moment, but `trunk-ng` has a bunch of fixes that `trunk` has
> not.

### Project

Clone the project, then:

```shell
npm ci
```

## Release build

Build the project:

```shell
trunk-ng build
```

If you are running on a sub-path, provide the base URL:

```shell
trunk-ng build --public-url https://foo/bar/baz
```

Deploy the content of the `deploy/` folder to a webserver.

## Developing

You will need a working backend in order to run the frontend. You can either use a locally running backend, to
get this working see the main documentation on running the project: [DEVELOPING.md](../../DEVELOPING.md).

Our you can point the frontend to use an existing backend. Create a file named `backend.local.json` in the folder
[endpoints](dev/endpoints) with the following content (or with URLs to a different backend, this is "staging"):

```json
{
  "url": "https://api.staging.trustification.dev",
  "bombastic": "https://sbom.staging.trustification.dev",
  "vexination": "https://vex.staging.trustification.dev"
}
```

**NOTE:** The version of the frontend must align with the version of the backend. Using the "staging" instance ensures
that you are closer to the current `main` branch. But even that might be out of date sometimes.

Then run it locally by executing:

```shell
trunk-ng serve
```

Navigate to: http://localhost:6030
