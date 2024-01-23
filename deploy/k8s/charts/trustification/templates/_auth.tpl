{{/*
Volume mounts for the authenticator configuration.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.authenticator.volumeMount" }}
- name: config-auth
  mountPath: /etc/config/auth.yaml

{{- if (.root.Values.authenticator.configMapRef).key }}
  subPath: {{ .root.Values.authenticator.configMapRef.key }}
{{- else if ((.module.authenticator).configMapRef).key }}
  subPath: {{ .module.authenticator.configMapRef.key }}
{{- else }}
  subPath: auth.yaml
{{ end }}
{{- end }}

{{/*
Volume for the authenticator configuration.

Arguments (dict):
  * root - .
  * name - name of the service
  * module - module object
*/}}
{{- define "trustification.authenticator.volume" }}
- name: config-auth
  configMap:
{{- if (.module.authenticator).configMapRef }}
    name: {{ .root.Values.authenticator.configMapRef.name }}
{{- else if .root.Values.authenticator.configMapRef }}
    name: {{ .root.Values.authenticator.configMapRef.name }}
{{- else }}
    name: {{ include "trustification.common.name" (set . "name" (printf "%s-auth" .name ) ) }}
{{- end }}
{{- end }}

{{- define "trustification.authenticator.defaultConfigMap" }}
{{- if and (not (.root.Values.authenticator).configMapRef) (not (.module.authenticator).configMapRef) }}

kind: ConfigMap
apiVersion: v1
metadata:
  name: {{ include "trustification.common.name" (set . "name" (printf "%s-auth" .name ) ) }}
  labels:
    {{- include "trustification.common.labels" (set . "name" (printf "%s-auth" .name ) ) | nindent 4 }}

data:

{{- if .module.authenticator }}{{/* if we have module specific config, that overrides the global */}}

{{- if .module.authenticator.content }}{{/* check for structured content */}}
  auth.yaml: |
    {{- .module.authenticator.content | toYaml | nindent 4 }}
{{- else }}
  auth.yaml: {{ .module.authenticator | quote }}
{{- end }}

{{- else if .root.Values.authenticator.content }}{{/* otherwise, use the global one */}}
  auth.yaml: |
    {{- .root.Values.authenticator.content | toYaml | nindent 4 }}{{/* check for structured content */}}
{{- else }}
  auth.yaml: {{ .root.Values.authenticator | quote }}
{{- end }}

{{- end }}{{/* external referenced config */}}

{{- end }}