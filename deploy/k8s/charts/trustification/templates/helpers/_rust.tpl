{{/*
Common env-vars for Rust based applications.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.application.rust.envVars" -}}
- name: RUST_LOG
  value: {{ .module.logFilter | default .root.Values.rustLogFilter | default "info" | quote }}
{{- end }}
