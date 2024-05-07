{{ define "trustification-infrastructure.keycloakPostInstall.url" -}}
http://{{ .Release.Name }}-keycloak.{{ .Release.Namespace }}.svc.cluster.local:80
{{- end }}

{{- define "trustification-infrastructure.keycloakPostInstall.defaultRedirectUrls" }}
{{- if $.Capabilities.APIVersions.Has "route.openshift.io/v1/Route" }}
- https://console{{ .Values.appDomain }}
- https://console{{ .Values.appDomain }}/*
- https://sbom{{ .Values.appDomain }}
- https://sbom{{ .Values.appDomain }}/*
- https://vex{{ .Values.appDomain }}
- https://vex{{ .Values.appDomain }}/*
{{- else }}
- http://localhost:*
- http://console{{ .Values.appDomain }}
- http://console{{ .Values.appDomain }}/*
- http://sbom{{ .Values.appDomain }}
- http://sbom{{ .Values.appDomain }}/*
- http://vex{{ .Values.appDomain }}
- http://vex{{ .Values.appDomain }}/*
{{- end }}
{{- end }}
