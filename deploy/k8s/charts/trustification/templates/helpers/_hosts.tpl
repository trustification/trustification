{{/*
Default host part of the documentation service.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.host.documentation" }}
{{- include "trustification.ingress.host" ( set (deepCopy .) "defaultHost" "docs") }}
{{- end }}

{{/*
Default host part of the SPoG API service.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.host.spogApi" }}
{{- include "trustification.ingress.host" ( set (deepCopy .) "defaultHost" "api") }}
{{- end }}

{{/*
Default host part of the SPoG UI service.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.host.spogUi" }}
{{- include "trustification.ingress.host" ( set (deepCopy .) "defaultHost" "console") }}
{{- end }}

{{/*
Default host part of the Bombastic API service.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.host.bombasticApi" }}
{{- include "trustification.ingress.host" ( set (deepCopy .) "defaultHost" "sbom") }}
{{- end }}

{{/*
Default host part of the Vexination API service.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.host.vexinationApi" }}
{{- include "trustification.ingress.host" ( set (deepCopy .) "defaultHost" "vex") }}
{{- end }}
