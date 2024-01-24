{{/*
Environment variables required to configure the HTTP server side.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.application.httpServer.envVars" -}}
- name: HTTP_SERVER_BIND_ADDR
  value: "::"

{{ if eq ( include "trustification.openshift.useServiceCa" .root ) "true" }}
- name: HTTP_SERVER_TLS_ENABLED
  value: "true"
- name: HTTP_SERVER_TLS_KEY_FILE
  value: "/etc/tls/tls.key"
- name: HTTP_SERVER_TLS_CERTIFICATE_FILE
  value: "/etc/tls/tls.crt"
{{ end }}

{{- end }}

{{/*
Volume mounts matching the HTTP server side configuration.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{ define "trustification.application.httpServerVolumesMounts" -}}

{{ if eq ( include "trustification.openshift.useServiceCa" .root ) "true" }}
- mountPath: /etc/tls
  name: tls
{{ end }}

{{- end }}

{{/*
Volumes matching the HTTP server side configuration.

Arguments (dict):
  * root - .
  * name - name of the deployment
  * module - module object
*/}}
{{ define "trustification.application.httpServerVolumes" -}}

{{ if eq ( include "trustification.openshift.useServiceCa" .root ) "true" }}
- name: tls
  secret:
    secretName: {{ .name }}-tls
{{- end }}

{{- end }}
