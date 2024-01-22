# Deploying

This is more a collection of notes rather than a proper documentation. Besides, neither CRC nor Minikube work at this
moment, for various reasons.

### With CRC

Get and setup `crc`, then start `crc`:

```shell
crc start --cpus 8 --memory 32768 --disk-size 80
```

Next, deploy the application:

```shell

cd deploy/k8s
helm dependency update charts/trustification
helm upgrade --install --debug -n trustification --create-namespace trustification charts/trustification --values values-crc.yaml
```

### With Minikube

**NOTE:** With Minikube there's currently no ingress. Which might make is pretty useless.

Start `minikube`:

```shell
minikube start --cpus 8 --memory 24576 --disk-size 20gb --addons ingress
```

In a new tab, start (and leave it running):

```shell
minikube tunnel
```

And, deploy the application:

```shell
helm upgrade --install -n trustification --create-namespace trustification charts/trustification --values values-minikube.yaml --set-string domain=$(minikube ip).nip.io
```
