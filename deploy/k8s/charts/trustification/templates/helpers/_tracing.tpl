{{/*
Is tracing enabled?

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{ define "trustification.application.tracing.enabled"}}
{{- if hasKey .module "tracing" }}
{{- if hasKey .module.tracing "enabled" }}
{{- .module.tracing.enabled }}
{{- else }}
{{- .root.Values.tracing.enabled }}
{{- end }}
{{- else -}}
false
{{- end }}
{{- end }}

{{/*
Annotations for tracing.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{ define "trustification.application.tracing.annotations" }}
{{- if eq (include "trustification.application.tracing.enabled" . ) "true" }}
sidecar.jaegertracing.io/inject: "true"
{{ end }}
{{- end }}
