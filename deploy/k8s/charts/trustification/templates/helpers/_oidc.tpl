
{{/*
Client ID for the frontend client.

Arguments: .
*/}}
{{- define "trustification.oidc.frontendClientId" -}}
{{- include "trustification.oidc.clientId" (dict "root" . "clientId" "frontend") }}
{{- end }}

{{/*
Client ID for some client

Arguments: (dict)
  * root - .
  * clientId - the client id to look up, might resolve into a different client id
*/}}
{{- define "trustification.oidc.clientId" }}
{{- $client := get .root.Values.oidc.clients .clientId -}}
{{- $client.clientId | default .clientId }}
{{- end }}

{{/*
Configuration required for setting up an OIDC client for making requests

Arguments (dict):
  * root - .
  * clientId - An ID, referecing a client in .Values.oidc.clients
*/}}
{{ define "trustification.oidc.authenticationClient" -}}

{{- $client := get .root.Values.oidc.clients .clientId -}}
{{- $clientId := $client.clientId | default .clientId }}

- name: OIDC_PROVIDER_CLIENT_ID
  {{- include "trustification.common.envVarValue" $clientId | nindent 2 }}
- name: OIDC_PROVIDER_CLIENT_SECRET
  {{- include "trustification.common.envVarValue" $client.clientSecret | nindent 2 }}

- name: OIDC_PROVIDER_ISSUER_URL
  value: {{ include "trustification.oidc.issuerUrl" ( dict "root" .root "client" $client ) }}

{{- if or $client.insecure .root.Values.oidc.insecure }}
- name: OIDC_PROVIDER_TLS_INSECURE
  value: "true"
{{- end }}

{{- with .root.Values.tls.additionalTrustAnchor }}
- name: OIDC_PROVIDER_TLS_CA_CERTIFICATES
  value: {{ . | quote }}
{{- end }}

{{- end }}

{{/*
Issuer URL for a specific client.

Arguments (dict):
  * root - .
  * client - client object
*/}}
{{- define "trustification.oidc.issuerUrl" }}
{{- if .client.issuerUrl }}
{{- .client.issuerUrl }}
{{- else if .root.Values.oidc.issuerUrl }}
{{- .root.Values.oidc.issuerUrl }}
{{- else -}}
{{ include "trustification.tls.http.protocol" . }}://sso{{ .root.Values.appDomain }}/realms/chicken
{{- end }}
{{- end }}

{{/*
Issuer URL for a specific client (by id)

Arguments (dict):
  * root - .
  * clientId - client id
*/}}
{{- define "trustification.oidc.issuerUrlForClient" }}
{{- $client := get .root.Values.oidc.clients .clientId -}}
{{- include "trustification.oidc.issuerUrl" ( dict "root" .root "client" (required (print "Unable to find client for " .clientId) $client ) ) }}
{{- end }}


{{/*
Issuer URL for the frontend client.

Arguments: .
*/}}
{{- define "trustification.oidc.frontendIssuerUrl" -}}
{{- include "trustification.oidc.issuerUrlForClient" (dict "root" . "clientId" "frontend" ) }}
{{- end }}

{{/*
"Value" part for an env-var, consuming the client secret.

Arguments (dict):
  * root - .
  * clientId - client id
*/}}
{{- define "trustification.oidc.clientSecretValue" }}
{{- $client := required (print "Unable to find client for " .clientId) (get .root.Values.oidc.clients .clientId)  -}}
{{- include "trustification.common.envVarValue" $client.clientSecret }}
{{- end }}


{{/*
"Value" part for an env-var, consuming the client secret.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.oidc.swaggerUi" }}

{{- if not .module.disableSwaggerOidc }}
- name: SWAGGER_UI_OIDC_ISSUER_URL
  value: {{ include "trustification.oidc.frontendIssuerUrl" .root | quote }}

{{- $client := required "Unable to find client for 'frontend'" (get .root.Values.oidc.clients "frontend" ) -}}

{{- if or $client.insecure .root.Values.oidc.insecure }}
- name: SWAGGER_UI_OIDC_TLS_INSECURE
  value: "true"
{{- end }}

{{- with .root.Values.tls.additionalTrustAnchor }}
- name: SWAGGER_UI_OIDC_TLS_CA_CERTIFICATES
  value: {{ . | quote }}
{{- end }}

{{- end }}{{/* if not .module.disableSwaggerOidc */}}

{{- end }}
