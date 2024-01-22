

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
- https://{{ .Values.spog.ui.host | default .Values.domain }}
- https://{{ .Values.spog.ui.host | default .Values.domain }}/*
- https://sbom.{{ .Values.domain }}
- https://sbom.{{ .Values.domain }}/*
- https://vex.{{ .Values.domain }}
- https://vex.{{ .Values.domain }}/*
{{- end }}
