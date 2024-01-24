{{/*
Environment variables required to configure the S3 storage

Arguments (dict):
  * root - .
  * module - module object

*/}}
{{- define "trustification.eventBus.envVars" -}}

{{- if .module.eventBus }}
{{- include "_trustification.eventBus.envVars" ( set (deepCopy .) "eventBus" .module.eventBus ) }}
{{- else }}
{{- include "_trustification.eventBus.envVars" ( set (deepCopy .) "eventBus" .root.Values.eventBus ) }}
{{- end }}

{{- end }}

{{/*
Environment variables required to configure the S3 storage

Arguments (dict):
  * root - .
  * module - module object
  * eventBus - an event bus configuration (either from the module or the global one)
*/}}
{{- define "_trustification.eventBus.envVars" -}}

{{- if eq .eventBus.type "kafka" }}

- name: EVENT_BUS
  value: kafka

- name: KAFKA_BOOTSTRAP_SERVERS
  value: {{ .eventBus.bootstrapServers | quote }}

{{- else if eq .eventBus.type "sqs" }}

- name: EVENT_BUS
  value: sqs

- name: SQS_ACCESS_KEY
  {{- include "trustification.common.envVarValue" .event.accessKey | nindent 2 }}
- name: SQS_SECRET_KEY
  {{- include "trustification.common.envVarValue" .event.secretKey | nindent 2 }}

- name: SQS_REGION
  value: {{ .eventBus.region | quote }}

{{- else }}
{{- fail ( print "Unsupported event bus type: " .eventBus.type ) }}
{{- end }}

{{- end }}