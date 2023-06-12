# RH prodesec SPDX crawler

## Usage
```shell
./walker.sh BOMBASTIC_INGEST_API_ADDRESS`
```

By default, it will get files listed [here](https://access.redhat.com/security/data/sbom/beta/index.txt).


## Container

Build with `podman build . -t trustification/rh-sbom-walker`
Run: 
```sehll
podman run --rm -it --net=host trustification/rh-sbom-walker localhost:8082
```
