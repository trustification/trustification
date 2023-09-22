# trustification.dev

Manifests for running trustification.dev

> [!NOTE]
> All deployment to trustification.dev should happen via the `staging` and `prod` workflows.

There are 3 environments isolated in 3 separate namespaces on the cluster:

* trustification-dev (dev.trustification.dev)
* trustification-staging (staging.trustification.dev)
* trustification.prod (trustification.dev)

Each of the environments have resources pre-created in AWS that they have access to, such as S3 buckets and SQS queues. If you for some reason need to delete and prune data, use the AWS console.

## Prerequisites

* [Kubernetes](k8s.io) ([OpenShift](openshift.com) if you want to expose using the Route resource)

## Deploying

Manual deploy to your own cluster:

```bash
helm upgrade --install -f dev.yaml trustification ../k8s/chart --namespace trustification-dev
```

## Continuous Deployment

The staging instance is automatically updated every night. Whenever a nightly or release build in the trustification repository runs, it will trigger the 'staging' workflow in this repository.

The staging workflow will update the release in the helm chart. On the cluster, ArgoCD will notice the new version and synchronize the charts.

> [!NOTE]
> The vexination-walker and bombastic-walker will both be started automatically if synchronization is complete, to re-fed the system. If there are index changes in the version being deployed, stale data may occur. 

## Production

The production deployment requires running the `prod` workflow. Once run, go to ArgoCD to manually sync the environment.

## Monitoring

All instances of trustification are monitored at [https://monitoring.trustification.dev](). There is a Grafana dashboard named 'Trustification', which can be used to find information about the systems. The source of that
dashboard can be found in the `dashboards/` folder in this repository.

## Alerting

There is no alerting configured for trustification.dev yet, but a few things worth checking regularly:

* Check if VEX and SBOM ingestion rates spike/increase after an ArgoCD sync is running. If they are completely flat, then have a look at the bombastic-walker or vexination-walker job logs for errors.

* Check if VEX and SBOM indexing failure rates have increased. If they have increased, look at the bombastic-indexer or vexination-indexer pod logs for errors.

* Check if the rate of HTTP errors from the APIs are spiking. If they have increased, look at the bombastic-api, vexination-api or spog-api pod logs for errors.

* Check if Spog UI data is showing data and that data makes sense. In some cases if index schema changes, there might be a period during re-feeding of data that information could be stale. This should resolve itself automatically unless there are bugs in walker or indexing.

## Troubleshooting

### post-install-keycloak job is failing

During the first install/deployment, the post-install-keycloak job might fail. In the logs, you will see entries like this: 

``` bash
Resource not found for url: http://trustification-staging-keycloak.trustification-staging.svc.cluster.local:80/admin/realms/chicken/identity-provider/instances/github
```

[The issue](https://github.com/keycloak/keycloak/issues/12484) relates to creating Keycloak identity providers from the command line. The workaround is to create the initial GitHub Identity Provider in the Keycloak admin UI. You can find the credentials for Keycloak stored in a Kubernetes secret. Then, go to "Identity Providers" and create it.

## License

Apache License, Version 2.0 ([LICENSE](LICENSE))
