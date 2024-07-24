{{/*
Default host part of the documentation service.

Arguments (dict):
  * root - .
*/}}
{{- define "trustification.host.documentation" }}
{{- include "trustification.ingress.host" (dict "root" .root "ingress" .root.Values.modules.documentation.ingress "defaultHost" "docs") }}
{{- end }}

{{/*
Default host part of the SPoG API service.

Arguments (dict):
  * root - .
*/}}
{{- define "trustification.host.spogApi" }}
{{- include "trustification.ingress.host" (dict "root" .root "ingress" .root.Values.modules.spogApi.ingress "defaultHost" "api") }}
{{- end }}

{{/*
Default host part of the SPoG UI service.

Arguments (dict):
  * root - .
*/}}
{{- define "trustification.host.spogUi" }}
{{- include "trustification.ingress.host" (dict "root" .root "ingress" .root.Values.modules.spogUi.ingress "defaultHost" "console") }}
{{- end }}

{{/*
Default host part of the Bombastic API service.

Arguments (dict):
  * root - .
*/}}
{{- define "trustification.host.bombasticApi" }}
{{- include "trustification.ingress.host" (dict "root" .root "ingress" .root.Values.modules.bombasticApi.ingress "defaultHost" "sbom") }}
{{- end }}

{{/*
Default host part of the Vexination API service.

Arguments (dict):
  * root - .
*/}}
{{- define "trustification.host.vexinationApi" }}
{{- include "trustification.ingress.host" (dict "root" .root "ingress" .root.Values.modules.vexinationApi.ingress "defaultHost" "vex") }}
{{- end }}


{{/*
Default host part of the report server.

Arguments (dict):
  * root - .
*/}}
{{- define "trustification.host.report" }}
{{- include "trustification.ingress.host" (dict "root" .root "ingress" .root.Values.modules.vexinationApi.ingress "defaultHost" "report") }}
{{- end }}
