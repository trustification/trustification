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
    name: {{ include "trustification.common.name" (set . "name" (printf "%s-auth" .name ) ) }}
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
  name: {{ include "trustification.common.name" (set . "name" (printf "%s-auth" .name ) ) }}
  labels:
    {{- include "trustification.common.labels" (set . "name" (printf "%s-auth" .name ) ) | nindent 4 }}

data:

{{- if .module.authenticator }}{{/* if we have module specific config, that overrides the global */}}

{{- if .module.authenticator.content }}{{/* check for structured content */}}
  auth.yaml: |
    {{- .module.authenticator.content | toYaml | nindent 4 }}
{{- else }}
  auth.yaml: {{ .module.authenticator | quote }}
{{- end }}

{{- else if .root.Values.authenticator }}{{/* if we have a global one, use that */}}

{{- if .root.Values.authenticator.content }}{{/* otherwise, use the global one */}}
  auth.yaml: |
    {{- .root.Values.authenticator.content | toYaml | nindent 4 }}{{/* check for structured content */}}
{{- else }}
  auth.yaml: {{ .root.Values.authenticator | quote }}
{{- end }}

{{- else }}{{/* otherwise we have no config, and try some reasonable defaults */}}
  auth.yaml: |
    authentication:
      clients:
        - clientId: frontend
          issuerUrl: {{ include "trustification.oidc.issuerUrlForClient" ( dict "root" .root "clientId" "frontend" ) }}
          scopeMappings: &keycloakScopeMappings
            "create:document": [ "create.sbom", "create.vex" ]
            "read:document": [ "read.sbom", "read.vex" ]
            "update:document": [ "update.sbom", "update.vex" ]
            "delete:document": [ "delete.sbom", "delete.vex" ]
        - clientId: walker
          issuerUrl: {{ include "trustification.oidc.issuerUrlForClient" ( dict "root" .root "clientId" "frontend" ) }}
          scopeMappings: *keycloakScopeMappings
{{- end }}

{{- end }}{{/* external referenced config */}}

{{- end }}