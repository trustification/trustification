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
Pod settings

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.application.pod" }}

{{- with .module.serviceAccountName }}
serviceAccountName: {{ . | quote }}
{{- end }}

{{- with .module.affinity }}
affinity:
  {{- . | toYaml | nindent 2 }}
{{- end }}

{{- end }}

{{/*
Default container settings

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.application.container" }}

{{- with .module.resources }}
resources:
  {{- . | toYaml | nindent 2 }}
{{ end }}

{{- end }}