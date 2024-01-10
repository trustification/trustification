# Development instructions

> Happy when helming? Most likely not!

**NOTE:** All commands are relative to this file.

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

## Testing locally

Start `minikube`:

```shell
minikube start --cpus 8 --memory 16318 --disk-size 20gb --addons ingress
minikube start --cpus 8 --memory 24576 --disk-size 20gb --addons ingress
```

In a new tab, start (and leave it running):

```shell
minikube tunnel
```

Then, create a new namespace:

```shell
kubectl create ns trustification
```

And, deploy the application:

```shell
helm upgrade --install -n trustification --create-namespace trustification chart/ --values values-minikube.yaml --set-string domain=$(minikube ip).nip.io
```
