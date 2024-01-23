# Development instructions

> Happy when helming? Most likely not!

**NOTE:** All commands are relative to this file.

## Updating chart dependencies

```shell
helm dependency update charts/trustification-infrastructure
```

## Updating the JSON schema

Unfortunately Helm requires the JSON schema to be authored in JSON. To make that a little bit easier, we author it
in YAML and then convert it to JSON. For example using:

```shell
python3 -c 'import sys, yaml, json; print(json.dumps(yaml.safe_load(sys.stdin)))' < charts/trustification/values.schema.yaml > charts/trustification/values.schema.json
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
