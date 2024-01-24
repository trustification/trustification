{{/*
Number of replicas.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.application.replicas" }}
{{- .root.Values.replicas | default .module.replicas | default 1 }}
{{- end }}

{{/*
Additional pod labels for applications.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.application.podLabels" }}
{{- include "trustification.application.metrics.podLabels" . }}
{{- end }}


{{/*
Resource section for applications.

Arguments (dict):
  * root -.
  * module - module object
*/}}
{{- define "trustification.application.resources" }}
{{- with .module.resources }}
resources:
  {{- . | toYaml | nindent 2 }}
{{ end }}
{{- end }}
