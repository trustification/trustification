{{/*
Default host part of the documentation service.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.host.documentation" }}
{{- include "trustification.ingress.host" ( set . "defaultHost" "docs") }}
{{- end }}

{{/*
Default host part of the SPoG API service.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.host.spogApi" }}
{{- include "trustification.ingress.host" ( set . "defaultHost" "spog-api") }}
{{- end }}
