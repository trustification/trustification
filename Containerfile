FROM ghcr.io/lulf/trustification-builder:latest as builder

RUN mkdir /usr/src/project
COPY . /usr/src/project
WORKDIR /usr/src/project

ARG tag
RUN TAG=$tag cargo build -p trust --release

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

LABEL org.opencontainers.image.source="https://github.com/trustification/trustification"

COPY --from=builder /usr/src/project/target/release/trust /
COPY --from=builder /usr/src/project/bombastic/walker/walker.sh /usr/bin
COPY --from=builder /usr/src/project/bombastic/walker/setup_gpg_key.sh /usr/bin/

ENV RUST_LOG info

ENTRYPOINT ["/trust"]
