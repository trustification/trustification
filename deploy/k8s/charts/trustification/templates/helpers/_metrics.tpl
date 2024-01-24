{{/*
Are metrics enabled?

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{ define "trustification.application.metrics.enabled"}}
{{- if hasKey .module.metrics "enabled" }}
{{- .module.metrics.enabled }}
{{- else }}
{{- .root.Values.metrics.enabled }}
{{- end }}
{{- end }}

{{/*
Pod labels for metrics.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{ define "trustification.application.metrics.podLabels" }}
{{- if eq (include "trustification.application.metrics.enabled" . ) "true" }}
metrics: "true"
{{ end }}
{{- end }}
