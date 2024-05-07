{{/*
Common env-vars for Rust based applications.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.application.rust.envVars" -}}
{{- $rust := merge (deepCopy .module.rust ) .root.Values.rust }}
- name: RUST_LOG
  value: {{ $rust.logFilter  | default "info" | quote }}
{{- if $rust.backtrace }}
- name: RUST_BACKTRACE
  value: "1"
{{- end }}
{{- end }}
