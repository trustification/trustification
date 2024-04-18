{{/*
Security Context constraints
https://docs.openshift.com/container-platform/4.15/authentication/managing-security-context-constraints.html
*/}}

{{- define "trustification.ocp.ssc" }}
{{ if .Values.securityContextConstraints.enabled }}
securityContext:
    allowPrivilegeEscalation: false
    capabilities:
        drop:
            - ALL
    privileged: false
    runAsNonRoot: true
    unAsUser: 1001
{{ end }}
{{ end }}
