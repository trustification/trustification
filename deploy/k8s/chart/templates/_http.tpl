{{/* Environment variables required to configure the HTTP server side */}}}
{{ define "trustification.http-server" -}}

- name: HTTP_SERVER_BIND_ADDR
  value: "::"
- name: HTTP_SERVER_TLS_ENABLED
  value: "true"
- name: HTTP_SERVER_TLS_KEY_FILE
  value: "/etc/tls/tls.key"
- name: HTTP_SERVER_TLS_CERTIFICATE_FILE
  value: "/etc/tls/tls.crt"

{{- end }}

{{/* Volume mounts matching the HTTP server side configuration */}}}
{{ define "trustification.http-server-volume-mounts" -}}

- mountPath: /etc/tls
  name: tls

{{- end }}

{{/* Volumes matching the HTTP server side configuration */}}}
{{ define "trustification.http-server-volumes" -}}
- name: tls
  secret:
    secretName: {{ .appName }}-tls
{{- end }}
