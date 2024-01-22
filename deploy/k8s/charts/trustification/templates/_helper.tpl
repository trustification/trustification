{{/* Arguments required to configure the client side authentication settings */}}}

{{ define "trustification.authentication-client" -}}

{{- $client := get .root.Values.oidcClients .clientId -}}

# OIDC client settings
- name: OIDC_PROVIDER_CLIENT_ID
  {{- if $client.clientId }}
  {{- $client.clientId | toYaml | nindent 2 }}
  {{- else }}
  value: {{ .clientId | quote }}
  {{- end }}
- name: OIDC_PROVIDER_CLIENT_SECRET
  {{- $client.clientSecret | toYaml | nindent 2 }}
- name: OIDC_PROVIDER_ISSUER_URL
  value: {{ $client.issuerUrl | quote }}

{{- if .root.Values.insecureSso }}
- name: OIDC_PROVIDER_INSECURE_TLS
  value: "true"
{{- end }}

{{- end }}

{{/* The client ID of the frontend client */}}
{{- define "trustification.authentication-frontend-client-id" -}}
{{- if .Values.oidcClients.frontend.clientId  }}
{{ .Values.oidcClients.frontend.clientId | toYaml }}
{{ else }}
value: frontend
{{- end }}
{{- end }}

{{/* The issuer URL of the frontend client */}}
{{- define "trustification.authentication-frontend-issuer-url" -}}
value: {{ .Values.oidcClients.frontend.issuerUrl | quote }}
{{- end }}
