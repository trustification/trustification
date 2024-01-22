# Development instructions

> Happy when helming? Most likely not!

**NOTE:** All commands are relative to this file.

## Updating chart dependencies

```shell
helm dependency update charts/trustification
```

## Linting Helm charts

```shell
helm lint ./charts/trustification
```

## Find that whitespace

```shell
helm template --debug charts/trustification
```

## Update the OpenShift templates

Helm charts are used to render the OpenShift templates in `../openshift`.

You can update those using:

```shell
make -C ../openshift
```

Read more in [../openshift/DEVELOPING.md](../openshift/DEVE****LOPING.md).
