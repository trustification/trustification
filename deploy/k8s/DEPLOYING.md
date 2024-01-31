# Deploying

## With Minikube

Start `minikube`:

```shell
minikube start --cpus 8 --memory 24576 --disk-size 20gb --addons ingress
```

Create a namespace:

```shell
kubectl create ns trustification
```

Then, deploy the application:

```shell
helm upgrade --install -n trustification infrastructure charts/trustification-infrastructure --values values-minikube.yaml --set-string keycloak.ingress.hostname=sso.$(minikube ip).nip.io --set-string appDomain=.$(minikube ip).nip.io
helm upgrade --install -n trustification trustification charts/trustification --values values-minikube.yaml --set-string appDomain=.$(minikube ip).nip.io
```

Speed up running initial jobs:

```shell
kubectl -n trustification create job --from=cronjob/v11y-walker v11y-walker-initial
kubectl -n trustification create job --from=cronjob/bombastic-collector bombastic-collector-initial
kubectl -n trustification create job --from=cronjob/vexination-collector vexination-collector-initial
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
APP_DOMAIN=-$NAMESPACE.$(kubectl -n openshift-ingress-operator get ingresscontrollers.operator.openshift.io default -o jsonpath='{.status.domain}')
helm upgrade --install -n $NAMESPACE infrastructure charts/trustification-infrastructure --values values-ocp-no-aws.yaml --set-string keycloak.ingress.hostname=sso$APP_DOMAIN --set-string appDomain=$APP_DOMAIN
helm upgrade --install -n $NAMESPACE trustification charts/trustification --values values-ocp-no-aws.yaml --set-string appDomain=$APP_DOMAIN
```
