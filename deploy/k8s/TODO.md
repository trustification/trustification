* [ ] Guac TLS

  ```
  --gql-tls-cert-file string   path to the TLS certificate in PEM format for graphql api server
  --gql-tls-key-file string    path to the TLS key in PEM format for graphql api server
  ```

  ```
  --csub-tls-cert-file string   path to the TLS certificate in PEM format for collect-sub service
  --csub-tls-key-file string    path to the TLS key in PEM format for collect-sub service
  ```

* [ ] GUAC Auth

  There is no auth. We need to apply some network policies.

* [X] Indexers - Kafka

  Missing support for access credentials properties, or any properties.

* [X] TLS/HTTPS support 
* [ ] Allow configuring multiple CSAF walkers
* [ ] Allow configuring multiple SBOM walkers
* [ ] Allow configuring the CVE walker
