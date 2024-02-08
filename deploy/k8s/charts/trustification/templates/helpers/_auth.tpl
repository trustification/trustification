{{/*
Volume mounts for the authenticator configuration.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.authenticator.volumeMount" }}
- name: config-auth
  mountPath: /etc/config/auth.yaml

{{- if ((.module.authenticator).configMapRef).key }}
  subPath: {{ .module.authenticator.configMapRef.key }}
{{- else if ((.root.Values.authenticator).configMapRef).key }}
  subPath: {{ .root.Values.authenticator.configMapRef.key }}
{{- else }}
  subPath: auth.yaml
{{ end }}
{{- end }}

{{/*
Volume for the authenticator configuration.

Arguments (dict):
  * root - .
  * name - name of the service
  * module - module object
*/}}
{{- define "trustification.authenticator.volume" }}
- name: config-auth
  configMap:
{{- if (.module.authenticator).configMapRef }}
    name: {{ .root.Values.authenticator.configMapRef.name }}
{{- else if (.root.Values.authenticator).configMapRef }}
    name: {{ .root.Values.authenticator.configMapRef.name }}
{{- else }}
    name: {{ include "trustification.common.name" (set (deepCopy .) "name" (printf "%s-auth" .name ) ) }}
{{- end }}
{{- end }}

{{/*
Create a default config map for the authenticator.

Arguments (dict):
  * root - .
  * name - name of the service
  * module - module object
*/}}
{{- define "trustification.authenticator.defaultConfigMap" }}
{{- if and (not (.root.Values.authenticator).configMapRef) (not (.module.authenticator).configMapRef) }}

kind: ConfigMap
apiVersion: v1
metadata:
  name: {{ include "trustification.common.name" (set (deepCopy .) "name" (printf "%s-auth" .name ) ) }}
  labels:
    {{- include "trustification.common.labels" (set (deepCopy .) "name" (printf "%s-auth" .name ) ) | nindent 4 }}

data:

{{ $auth := .module.authenticator | default .root.Values.authenticator }}

{{- if kindIs "string" $auth }} {{/* Plain string */}}
  auth.yaml: {{ $auth | quote }}

{{- else if hasKey $auth "content" }} {{/* Structured content */}}
  auth.yaml: |
    {{ $auth | toYaml | nindent 4 }}

{{- else }} {{/* Empty */}}
  auth.yaml: |
    {{- include "trustification.authenticator.defaultContent" . | nindent 4 }}

{{- end }}

{{- end }}{{/* external referenced config */}}
{{- end }}

{{/*
Create the authenticator default configuration.

Arugments: (dict)
  * root - .
  * module - module object
*/}}
{{- define "trustification.authenticator.defaultContent" }}

{{- if eq (.root.Values.authenticator).type "cognito" -}}
authentication:
  clients:
    - clientId: {{ include "trustification.oidc.clientId" (dict "root" .root "clientId" "frontend" ) }}
      issuerUrl: {{ include "trustification.oidc.issuerUrlForClient" (dict "root" .root "clientId" "frontend" ) }}

      additionalPermissions:
        - "read.sbom"
        - "read.vex"
        - "read.cve"

      groupSelector: "$.['cognito:groups'][*]"

      groupMappings:
        manager:
          - "create.sbom"
          - "create.vex"
          - "update.sbom"
          - "update.vex"
          - "delete.sbom"
          - "delete.vex"

    - clientId: {{ include "trustification.oidc.clientId" (dict "root" .root "clientId" "walker" ) }}
      issuerUrl: {{ include "trustification.oidc.issuerUrlForClient" (dict "root" .root "clientId" "walker" ) }}

      scopeMappings:
        "trustification/bombastic":
          - "create.sbom"
          - "read.sbom"
          - "update.sbom"
          - "delete.sbom"
        "trustification/vexination":
          - "create.vex"
          - "read.vex"
          - "update.vex"
          - "delete.vex"
        "trustification/v11y":
          - "read.cve"

{{- else -}}{{/* Keycloak is the default */}}
authentication:
  clients:
    - clientId: {{ include "trustification.oidc.clientId" (dict "root" .root "clientId" "frontend" ) }}
      issuerUrl: {{ include "trustification.oidc.issuerUrlForClient" (dict "root" .root "clientId" "frontend" ) }}
      scopeMappings: &keycloakScopeMappings
        "create:document": [ "create.sbom", "create.vex" ]
        "read:document": [ "read.sbom", "read.vex" ]
        "update:document": [ "update.sbom", "update.vex" ]
        "delete:document": [ "delete.sbom", "delete.vex" ]
    - clientId: {{ include "trustification.oidc.clientId" (dict "root" .root "clientId" "walker" ) }}
      issuerUrl: {{ include "trustification.oidc.issuerUrlForClient" (dict "root" .root "clientId" "walker" ) }}
      scopeMappings: *keycloakScopeMappings

{{- end }}
{{- end }}
