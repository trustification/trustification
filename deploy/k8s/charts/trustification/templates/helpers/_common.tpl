{{/*
Create an env-var value, either from a string, or by providing the full value section.

Arguments: string or object
*/}}
{{- define "trustification.common.envVarValue" }}

{{- if kindIs "string" . }}{{/* if it's a string, we use it as value */}}
value: {{ . | quote }}
{{- else if empty . }}{{/* if it's empty, we drop the value section */}}
{{- else }}
{{ . | toYaml }}{{/* otherwise, it must be an oject */}}
{{- end }}

{{- end }}
