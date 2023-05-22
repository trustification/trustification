FROM registry.access.redhat.com/ubi9/ubi-minimal:latest as builder

ARG tag

RUN microdnf install -y gcc openssl openssl-devel cmake gcc-c++
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal
ENV PATH "$PATH:/root/.cargo/bin"
LABEL org.opencontainers.image.source="https://github.com/trustification/bombastic"

RUN mkdir /usr/src/project
COPY . /usr/src/project
WORKDIR /usr/src/project

RUN TAG=$tag cargo build --release


FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

LABEL org.opencontainers.image.source="https://github.com/trustification/bombastic"

COPY --from=builder /usr/src/project/target/release/bombastic /

ENV RUST_LOG info
EXPOSE 8080

ENTRYPOINT ["/bombastic"]
