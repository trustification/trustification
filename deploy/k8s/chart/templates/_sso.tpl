

{{/* Environment variables required to configure the HTTP server side */}}}
{{ define "trustification.sso.redirect-uris" -}}
{{- if .Values.ssoDefaults -}}
{{ include "trustification.sso.default-redirect-uris" . | fromYamlArray | toJson }}
{{- else }}
{{- .Values.keycloakRealm.redirectUris | toJson }}
{{- end }}
{{- end }}

{{ define "trustification.sso.default-redirect-uris" }}
- http://localhost:*
- http://{{ .Values.domain }}
- http://{{ .Values.domain }}/*
- http://sbom.{{ .Values.domain }}
- http://sbom.{{ .Values.domain }}/*
- http://vex.{{ .Values.domain }}
- http://vex.{{ .Values.domain }}/*
{{- end }}
