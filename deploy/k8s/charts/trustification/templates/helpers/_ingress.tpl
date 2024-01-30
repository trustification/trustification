{{/*
Ingress class name, with field

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{ define "trustification.ingress.className" }}
{{- with .module.ingress.className | default .root.Values.ingress.className }}
ingressClassName: {{ . | quote }}
{{- end }}
{{- end }}

{{/*
Hostname for a common service

Arguments (dict):
  * root - .
  * defaultHost - default name of the host (in addition to the domain)
  * ingress - default ingress object
*/}}
{{ define "trustification.ingress.host" }}
{{- with .ingress.host }}
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
  * tlsMode - (edge or reencrypt)
*/}}
{{- define "trustification.ingress.defaultIngress" }}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "trustification.common.name" . }}
  labels:
    {{- include "trustification.common.labels" . | nindent 4 }}
  annotations:
    {{- with .module.ingress.additionalAnnotations | default .root.Values.ingress.additionalAnnotations }}
    {{- . | toYaml | nindent 4 }}
    {{- end }}

    {{- if eq (include "trustification.openshift.useServiceCa" .root ) "true" }}
    {{- if eq .tlsMode "edge" }}
    route.openshift.io/termination: edge
    {{- else if or ( eq .tlsMode "reencrypt" ) (empty .tlsMode) }}
    route.openshift.io/termination: reencrypt
    {{- else }}
    {{- fail ( print "Unsupported TLS mode: " .tlsMode ) }}
    {{- end }}
    {{- end }}

spec:
  {{- include "trustification.ingress.className" . | nindent 2 }}
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