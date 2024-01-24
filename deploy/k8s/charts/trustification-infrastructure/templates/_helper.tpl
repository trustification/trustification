{{ define "trustification-infrastructure.keycloakPostInstall.url" -}}
http://{{ .Release.Name }}-keycloak.{{ .Release.Namespace }}.svc.cluster.local:80
{{- end }}

{{- define "trustification-infrastructure.keycloakPostInstall.defaultRedirectUrls" }}
- http://localhost:*
- http://console{{ .Values.appDomain }}
- http://console{{ .Values.appDomain }}/*
- http://sbom{{ .Values.appDomain }}
- http://sbom{{ .Values.appDomain }}/*
- http://vex{{ .Values.appDomain }}
- http://vex{{ .Values.appDomain }}/*
{{- end }}
