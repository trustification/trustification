{{/*
Default GUAC image

Arguments (dict):
  * root - .
  * imageName - (optional) the base name of the image
  * module - module object
*/}}
{{- define "trustification.guac.defaultImage" }}
{{- include "trustification.common.image" ( dict "root" .root "image" .module.image "imageName" .imageName "defaults" .root.Values.guac.image )}}
{{- end }}


{{/*
Additional env-vars for configuring the Guac GraphQL.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.guac.graphql.envVars"}}
{{- if eq ( include "trustification.openshift.useServiceCa" .root ) "true" }}
- name: GUAC_GQL_TLS_CERT_FILE
  value: /etc/tls/tls.crt
- name: GUAC_GQL_TLS_KEY_FILE
  value: /etc/tls/tls.key
{{- end }}
- name: GUAC_PROMETHEUS_ADDR
  value: {{ include "trustification.application.infrastructure.port" . | quote }}
{{- end }}


{{/*
Additional env-vars for configuring the Guac clients.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.guac.client.envVars"}}
{{- if eq ( include "trustification.openshift.useServiceCa" .root ) "true" }}
- name: GUAC_CSUB_TLS_ROOT_CA
  value: /run/secrets/kubernetes.io/serviceaccount/service-ca.crt
- name: GUAC_GQL_TLS_ROOT_CA
  value: /run/secrets/kubernetes.io/serviceaccount/service-ca.crt
{{- end }}
{{- end }}