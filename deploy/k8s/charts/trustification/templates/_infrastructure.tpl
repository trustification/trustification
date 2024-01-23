{{/*
Additional env-vars for configuring the infrastructure endpoint.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.application.infrastructure.envVars"}}
- name: INFRASTRUCTURE_ENABLED
  value: "true"
- name: INFRASTRUCTURE_BIND
  value: "[::]:9010"

{{- if eq ( include "trustification.application.tracing.enabled" . ) "true" }}
- name: TRACING
  value: "true"
- name: OTEL_BSP_MAX_EXPORT_BATCH_SIZE
  value: "32"
- name: OTEL_TRACES_SAMPLER
  value: parentbased_traceidratio
- name: OTEL_TRACES_SAMPLER_ARG
  value: "0.1"
{{- end }}

{{- end }}

{{/*
Pod port definition for the infrastructure endpoint.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.application.infrastructure.podPorts" }}
- containerPort: 9010
  protocol: TCP
  name: infra
{{- end}}

{{/*
Standard infrastructure probe definitions.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{ define "trustification.application.infrastructure.probes" }}
livenessProbe:
  initialDelaySeconds: 2
  httpGet:
    path: /health/live
    port: 9010

readinessProbe:
  initialDelaySeconds: 2
  httpGet:
    path: /health/ready
    port: 9010

startupProbe:
  httpGet:
    path: /health/startup
    port: 9010
{{- end }}
