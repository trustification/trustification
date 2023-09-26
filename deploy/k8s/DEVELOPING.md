# Development instructions

> Happy when helming? Most likely not! 

## Updating chart dependencies

```shell
helm dependency update chart/
```

## Linting Helm charts

```shell
helm lint ./chart -f ./chart/trustification.dev/staging.yaml
helm lint ./chart -f ./chart/trustification.dev/prod.yaml
```

## Find that whitespace

```shell
helm template --debug chart/ -f chart/staging.yaml # or prod.yaml
```
