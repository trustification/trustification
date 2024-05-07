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

- name: KAFKA_PROPERTIES_ENV_PREFIX
  value: TCK_

- name: TCK_SECURITY__PROTOCOL
  value: {{ .eventBus.config.securityProtocol }}

{{- if eq .eventBus.config.securityProtocol "SASL_PLAINTEXT" }}

- name: TCK_SASL__USERNAME
  {{- include "trustification.common.envVarValue" .eventBus.config.username | nindent 2 }}

- name: TCK_SASL__PASSWORD
  {{- include "trustification.common.envVarValue" .eventBus.config.password | nindent 2 }}

- name: TCK_SASL__MECHANISM
  {{- include "trustification.common.envVarValue" .eventBus.config.mechanism | nindent 2 }}

{{- end }}

{{- else if eq .eventBus.type "sqs" }}

- name: EVENT_BUS
  value: sqs

- name: SQS_ACCESS_KEY
  {{- include "trustification.common.envVarValue" .eventBus.accessKey | nindent 2 }}
- name: SQS_SECRET_KEY
  {{- include "trustification.common.envVarValue" .eventBus.secretKey | nindent 2 }}

- name: SQS_REGION
  value: {{ .eventBus.region | quote }}

{{- else }}
{{- fail ( print "Unsupported event bus type: " .eventBus.type ) }}
{{- end }}

{{- end }}


{{/*
Environment variables required to configure the S3 storage. GUAC edition.

Arguments (dict):
  * root - .
  * module - module object

*/}}
{{- define "trustification.eventBus.guac.envVars" -}}

{{- if .module.eventBus }}
{{- include "_trustification.eventBus.guac.envVars" ( set (deepCopy .) "eventBus" .module.eventBus ) }}
{{- else }}
{{- include "_trustification.eventBus.guac.envVars" ( set (deepCopy .) "eventBus" .root.Values.eventBus ) }}
{{- end }}

{{- end }}

{{/*
Environment variables required to configure the S3 storage. GUAC edition.

Arguments (dict):
  * root - .
  * module - module object
  * eventBus - an event bus configuration (either from the module or the global one)
*/}}
{{- define "_trustification.eventBus.guac.envVars" -}}

{{- if eq .eventBus.type "kafka" }}

- name: GUAC_S3_MP
  value: kafka

- name: GUAC_S3_MP_ENDPOINT
  value: {{ .eventBus.bootstrapServers | quote }}

- name: KAFKA_PROPERTIES_ENV_PREFIX
  value: TCK_

- name: TCK_SECURITY__PROTOCOL
  value: {{ .eventBus.config.securityProtocol }}

{{- if eq .eventBus.config.securityProtocol "SASL_PLAINTEXT" }}

- name: TCK_SASL__USERNAME
  {{- include "trustification.common.envVarValue" .eventBus.config.username | nindent 2 }}

- name: TCK_SASL__PASSWORD
  {{- include "trustification.common.envVarValue" .eventBus.config.password | nindent 2 }}

- name: TCK_SASL__MECHANISM
  {{- include "trustification.common.envVarValue" .eventBus.config.mechanism | nindent 2 }}

{{- end }}

{{- else if eq .eventBus.type "sqs" }}

- name: GUAC_S3_MP
  value: sqs

- name: SQS_ACCESS_KEY
  {{- include "trustification.common.envVarValue" .eventBus.accessKey | nindent 2 }}
- name: SQS_SECRET_KEY
  {{- include "trustification.common.envVarValue" .eventBus.secretKey | nindent 2 }}

- name: SQS_REGION
  value: {{ .eventBus.region | quote }}

{{- else }}
{{- fail ( print "Unsupported event bus type: " .eventBus.type ) }}
{{- end }}

{{- end }}

