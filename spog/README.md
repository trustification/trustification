# SPoG

## GUAC

First you have to build guac, at least once:

```shell
rm -Rf guac
git clone -b trust-api https://github.com/xkcd-2347/guac
podman build guac -f guac/dockerfiles/Dockerfile.guac-ubi -t localhost/guac:latest
```

## Running

Start up GUAC:

```shell
# podman run -p 6010:8080 --name guac -ti localhost/guac:latest gql-server --gql-debug
podman run -p 8080:8080 --name guac -ti localhost/guac:latest /opt/guac/guacgql --gql-debug
```

Ingest some data:

```shell
podman run --net=host -v $PWD/example-data:/data:Z --rm -ti localhost/guac:latest /opt/guac/guacone collect files /data
podman run --net=host --rm -ti localhost/guac:latest osv -p=false
```

Run the API server:

```shell
cargo run --package spog-api -- run --port 6020
```

Next run the frontend:

```shell
cd ui
trunk serve
```

## Stopping

```shell
podman stop guac
podman rm guac 
```
