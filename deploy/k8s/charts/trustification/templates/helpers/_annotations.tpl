{{/*
Common application annotations

Arguments (dict):
  * root - .
  * name - name of the resource
  * module - module object
*/}}
{{ define "trustification.application.annotations" }}
{{ include "trustification.application.tracing.annotations" . }}
{{- end }}