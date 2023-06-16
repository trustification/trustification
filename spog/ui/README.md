# Chicken coop

## Setting up

### Toolchain

[Install Rust](https://www.rust-lang.org/tools/install), then:

```shell
rustup target add wasm32-unknown-unknown
cargo install trunk
```

### Project

Clone the project, then:

```shell
npm ci
```

## Release build

Build the project:

```shell
trunk build
```

If you are running on a sub-path, provide the base URL:

```shell
trunk build --public-url https://foo/bar/baz
```

Deploy the content of the `deploy/` folder to a webserver.

## Developing

Running locally:

```shell
trunk serve
```

Then navigate to: http://localhost:6030

