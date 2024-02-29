# Deploying

## Minikube

Start `minikube`:

```shell
minikube start --cpus 8 --memory 24576 --disk-size 20gb --addons ingress,dashboard
```

Create a namespace:

```shell
kubectl create ns trustification
```

Then, deploy the application:

```shell
helm upgrade --install --dependency-update -n trustification infrastructure charts/trustification-infrastructure --values values-minikube.yaml --set-string keycloak.ingress.hostname=sso.$(minikube ip).nip.io --set-string appDomain=.$(minikube ip).nip.io
helm upgrade --install -n trustification trustification charts/trustification --values values-minikube.yaml --set-string appDomain=.$(minikube ip).nip.io
```

Speed up running initial jobs:

```shell
kubectl -n trustification create job --from=cronjob/v11y-walker v11y-walker-initial
```

Once it is installed, you can open the SPoG UI console at: `http://console.$(minikube ip).nip.io`, using the credentials
from the values file.

## Kind

It is also possible to use `kind` instead of `minikube`.

Start the cluster:

```shell
kind create cluster --config=.github/kind-config.yaml
```

Then install the NGINX ingress controller:

```shell
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/86f3af8dead82f2d0905dceddeba213751e15b50/deploy/static/provider/kind/deploy.yaml
```

And wait until it is up:

```shell
kubectl wait --namespace ingress-nginx --for=condition=ready pod --selector=app.kubernetes.io/component=controller --timeout=90s
```

Workaround for [helm#10733](https://github.com/helm/helm/issues/10733):

```shell
kubectl create -f - << __EOF__
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-workaround
spec:
  accessModes:
  - ReadWriteOnce
  capacity:
    storage: 20Gi
  claimRef:
    apiVersion: v1
    kind: PersistentVolumeClaim
    name: v11y-walker
    namespace: trustification
  persistentVolumeReclaimPolicy: Delete
  storageClassName: standard
  volumeMode: Filesystem
  hostPath:
    type: DirectoryOrCreate
    path: /var/local-path-provisioner/pvc-workaround
__EOF__
```

Create a namespace:

```shell
kubectl create ns trustification
```

Then, deploy the application:

```shell
APP_DOMAIN=.$(kubectl get node kind-control-plane -o jsonpath='{.status.addresses[?(@.type == "InternalIP")].address}' | awk '// { print $1 }').nip.io
helm upgrade --install --dependency-update -n trustification infrastructure charts/trustification-infrastructure --values values-minikube.yaml --set-string keycloak.ingress.hostname=sso$APP_DOMAIN --set-string appDomain=$APP_DOMAIN
helm upgrade --install -n trustification trustification charts/trustification --values values-minikube.yaml --set-string appDomain=$APP_DOMAIN
```

## OpenShift (without AWS)

Ensure you are logged in to an OpenShift cluster and have the permission to create new projects and workload.

Create a namespace:

```shell
oc new-project trustification
```

Then, deploy the application:

```shell
# APP_DOMAIN=""
NAMESPACE=trustification
APP_DOMAIN=-$NAMESPACE.$(oc -n openshift-ingress-operator get ingresscontrollers.operator.openshift.io default -o jsonpath='{.status.domain}')
helm upgrade --install --dependency-update -n $NAMESPACE infrastructure charts/trustification-infrastructure --values values-ocp-no-aws.yaml --set-string keycloak.ingress.hostname=sso$APP_DOMAIN --set-string appDomain=$APP_DOMAIN
helm upgrade --install -n $NAMESPACE trustification charts/trustification --values values-ocp-no-aws.yaml --set-string appDomain=$APP_DOMAIN
```

## Branding

Install the branding Helm chart using:

```shell
helm upgrade --install -n trustification branding charts/trustification-branding
```
