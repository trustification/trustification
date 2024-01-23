{{/*
Hostname for the documentation module

Arguments (dict):
  * root - .
  * name - name of the resource
*/}}
{{ define "trustification.module.documentation.host" }}
{{- with .module.ingress.host }}
{{- . }}
{{- else -}}
docs{{- .root.Values.appDomain }}
{{- end }}
{{- end }}

