{{/*
Postgres configuration env-vars.

Arguments (dict):

  * root - .
  * database - database object
  * prefix - (optional) prefix to the env-var names
*/}}
{{- define "trustification.postgres.envVars" }}
- name: {{ .prefix | default "" }}PGHOST
  {{- include "trustification.common.requiredEnvVarValue" (dict "value" .database.host "msg" "Missing value for database host" ) | nindent 2 }}
- name: {{ .prefix | default "" }}PGPORT
  {{- include "trustification.common.envVarValue" (.database.port | default "5432") | nindent 2 }}
- name: {{ .prefix | default "" }}PGDATABASE
  {{- include "trustification.common.requiredEnvVarValue" (dict "value" .database.name "msg" "Missing value for database name" ) | nindent 2 }}
- name: {{ .prefix | default "" }}PGUSER
  {{- include "trustification.common.requiredEnvVarValue" (dict "value" .database.username "msg" "Missing value for database username" ) | nindent 2 }}
- name: {{ .prefix | default "" }}PGPASSWORD
  {{- include "trustification.common.requiredEnvVarValue" (dict "value" .database.password "msg" "Missing value for database password" ) | nindent 2 }}

{{/*
NOTE: The mode "allow" is not support by Go
*/}}
- name: {{ .prefix | default "" }}PGSSLMODE
  value: disable

{{- end }}