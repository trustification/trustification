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

## Update the OpenShift templates

Helm charts are used to render the OpenShift templates in `../openshift`.

You can update those using:

```shell
make -C ../openshift
```

Read more in [../openshift/DEVELOPING.md](../openshift/DEVE****LOPING.md).