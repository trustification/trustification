{{/*
Postgres configuration env-vars.

Arguments (dict):

  * root - .
  * module - module object
  * defaults - database defaults

*/}}
{{- define "trustification.postgres.envVars" }}
- name: PGHOST
  {{- include "trustification.common.requiredEnvVarValue" (dict "value" ( (.module.database).host | default .defaults.host ) "msg" "Missing value for database host" ) | nindent 2 }}
- name: PGPORT
  {{- include "trustification.common.envVarValue" ( (.module.database).port | default .defaults.port | default "5432" ) | nindent 2 }}
- name: PGDATABASE
  {{- include "trustification.common.requiredEnvVarValue" (dict "value" ( (.module.database).name | default .defaults.name ) "msg" "Missing value for database name" ) | nindent 2 }}
- name: PGUSER
  {{- include "trustification.common.requiredEnvVarValue" (dict "value" ( (.module.database).username | default .defaults.username ) "msg" "Missing value for database username" ) | nindent 2 }}
- name: PGPASSWORD
  {{- include "trustification.common.requiredEnvVarValue" (dict "value" ( (.module.database).password | default .defaults.password ) "msg" "Missing value for database password" ) | nindent 2 }}

{{- end }}