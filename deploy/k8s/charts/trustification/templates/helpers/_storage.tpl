{{/*
Environment variables required to configure the S3 storage

Arguments (dict):
  * root - .
  * module - module object
  * storage - global storage config (.bombastic/.vexination)
*/}}
{{ define "trustification.storage.envVars" -}}

{{- if .module.storage }}
{{- include "_trustification.storage.envVars" ( set (deepCopy .) "storage" .module.storage ) }}
{{- else }}
{{- include "_trustification.storage.envVars" ( set (deepCopy .) "storage" .root.Values.storage ) }}
{{- end }}

- name: STORAGE_BUCKET
{{- if .module.storage }}
  value: {{ .module.storage.bucket | default .storage.bucket | quote }}
{{- else }}
  value: {{ .storage.bucket | quote }}
{{- end}}

{{- end }}

{{- define "_trustification.storage.envVars" -}}

- name: STORAGE_ACCESS_KEY
  {{- include "trustification.common.envVarValue" .storage.accessKey | nindent 2 }}

- name: STORAGE_SECRET_KEY
  {{- include "trustification.common.envVarValue" .storage.secretKey | nindent 2 }}

{{ if .storage.endpoint }}
- name: STORAGE_ENDPOINT
  value: {{ .storage.endpoint | quote }}
- name: STORAGE_REGION
  value: "eu-west-1" # just a dummy value
{{ else }}
- name: STORAGE_REGION
  value: "{{ .storage.region }}"
{{ end }}

{{- end }}

{{/*
Environment variables required to configure the S3 storage, GUAC edition

Arguments (dict):
  * root - .
  * module - module object
  * storage - global storage config (.bombastic/.vexination)
*/}}
{{ define "trustification.storage.guac.envVars" -}}

{{- if .module.storage }}
{{- include "_trustification.storage.guac.envVars" ( set (deepCopy .) "storage" .module.storage ) }}
{{- else }}
{{- include "_trustification.storage.guac.envVars" ( set (deepCopy .) "storage" .root.Values.storage ) }}
{{- end }}

- name: GUAC_S3_BUCKET
{{- if .module.storage }}
  value: {{ .module.storage.bucket | default .storage.bucket | quote }}
{{- else }}
  value: {{ .storage.bucket | quote }}
{{- end}}

{{- end }}

{{- define "_trustification.storage.guac.envVars" -}}

- name: STORAGE_ACCESS_KEY
  {{- include "trustification.common.envVarValue" .storage.accessKey | nindent 2 }}
- name: STORAGE_SECRET_KEY
  {{- include "trustification.common.envVarValue" .storage.secretKey | nindent 2 }}

{{ if .storage.endpoint }}
- name: GUAC_S3_URL
  value: {{ .storage.endpoint | quote }}
{{ else }}
- name: STORAGE_REGION
  value: "{{ .storage.region }}"
- name: STORAGE_REGION
  value: "{{ .storage.region }}"
{{ end }}

{{- end }}
