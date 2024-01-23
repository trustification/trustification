{{ define "trustification-infrastructure.keycloakPostInstall.url" -}}
http://{{ .Release.Name }}-keycloak.{{ .Release.Namespace }}.svc.cluster.local:80
{{- end }}