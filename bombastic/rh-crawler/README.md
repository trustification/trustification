# RH prodesec SPDX crawler

## Usage
```shell
./crawler.sh BOMBASTIC_INGEST_API_ADDRESS`
```

By default, it will get files listed [here](https://access.redhat.com/security/data/sbom/beta/index.txt).


## Container

Build with `podman build . -t trustification/rh-sbom-crawler`
Run: 
```sehll
podman run --rm -it --net=host trustification/rh-sbom-crawler localhost:8082
```
