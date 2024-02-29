{{/*
Create an env-var value, either from a string, or by providing the full value section.

Arguments: string or object
*/}}
{{- define "trustification.common.envVarValue" }}

{{- if kindIs "string" . }}{{/* if it's a string, we use it as value */ -}}
value: {{ . | quote }}
{{- else if empty . }}{{/* if it's empty, we drop the value section */ -}}
{{- else }}
{{- . | toYaml }}{{/* otherwise, it must be an oject */ -}}
{{- end }}

{{- end }}

{{/*
Create an env-var value, either from a string, or by providing the full value section.

Arguments: (dict)
  * value - the value
  * msg - error message when value is missing
*/}}
{{- define "trustification.common.requiredEnvVarValue" }}
{{- $_ := required .msg .value }}
{{- include "trustification.common.envVarValue" .value }}
{{- end }}

{{/*
Byte-size as a string value.

Arguments: int or string
*/}}
{{- define "trustification.common.byteSizeValue" }}
{{ . | quote }}
{{- end }}
