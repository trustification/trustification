{{/*
Issuer URL for the frontend client.

Arguments: .
*/}}
{{- define "trustification.oidc.frontendIssuerUrl" -}}
{{- $client := get .Values.oidc.clients "frontend" -}}
{{- include "trustification.oidc.issuerUrl" (dict "root" . "client" $client ) -}}
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

# OIDC client settings
- name: OIDC_PROVIDER_CLIENT_ID
  {{- include "trustification.common.envVarValue" $clientId | nindent 2 }}
- name: OIDC_PROVIDER_CLIENT_SECRET
  {{- include "trustification.common.envVarValue" $client.clientSecret | nindent 2 }}

- name: OIDC_PROVIDER_ISSUER_URL
  value: {{ include "trustification.oidc.issuerUrl" ( dict "root" .root "client" $client ) }}

{{- if or $client.insecure .root.Values.oidc.insecure }}
- name: OIDC_PROVIDER_INSECURE_TLS
  value: "true"
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
{{- .client.issuerUrl | quote }}
{{- else if .root.Values.oidc.issuerUrl }}
{{- .root.Values.oidc.issuerUrl | quote }}
{{- else -}}
http://sso{{ .root.Values.appDomain }}/realms/chicken
{{- end }}
{{- end }}
