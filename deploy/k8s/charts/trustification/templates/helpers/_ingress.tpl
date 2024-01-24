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

{{/*
Hostname for a common service

Arguments (dict):
  * root - .
  * defaultHost - default name of the host (in addition to the domain)
  * module - module object
*/}}
{{ define "trustification.ingress.host" }}
{{- with .module.ingress.host }}
{{- . }}
{{- else -}}
{{- .defaultHost }}{{- .root.Values.appDomain }}
{{- end }}
{{- end }}

{{/*
A default ingress definion.

Arguments (dict):
  * root - .
  * name - default name of the application/service
  * host - the host name
  * module - module object
*/}}
{{- define "trustification.ingress.defaultIngress" }}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "trustification.common.name" . }}
  labels:
    {{- include "trustification.common.labels" . | nindent 4 }}
spec:
  {{ include "trustification.ingress.className" . }}
  rules:
    - host: {{ .host | quote }}
      http:
        paths:
          - pathType: Prefix
            path: /
            backend:
              service:
                name: {{ include "trustification.common.name" . }}
                port:
                  name: endpoint
{{- end }}