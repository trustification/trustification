FROM ghcr.io/ctron/trunk:latest as builder

RUN mkdir /usr/src/console

COPY . /usr/src/console

WORKDIR /usr/src/console

RUN true \
    && npm ci \
    && trunk build --release --dist /public

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

LABEL org.opencontainers.image.source="https://github.com/xkcd-2347/chicken-coop"

RUN microdnf install -y nginx jq

RUN true \
    && mkdir /public \
    && mkdir /endpoints

COPY --from=builder /public /public/
COPY config/nginx.conf /etc/nginx/nginx.conf

COPY config/nginx.sh /nginx.sh
RUN chmod a+x /nginx.sh

EXPOSE 80

CMD [ "/nginx.sh" ]
