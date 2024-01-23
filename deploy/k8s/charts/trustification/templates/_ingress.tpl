{{/*
Ingress class name, with field

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{ define "trustification.ingress.className" }}
{{- with .module.ingress.className | default .root.Values.ingress.className }}
ingressClassName: {{- . }}
{{- end }}
{{- end }}
