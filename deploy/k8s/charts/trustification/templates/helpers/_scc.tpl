{{/*
Security Context constraints
https://docs.openshift.com/container-platform/4.15/authentication/managing-security-context-constraints.html
*/}}

{{- define "trustification.ocp.ssc" }}
{{ if .Values.securityContextConstraintsEnabled }}
securityContext:
    allowPrivilegeEscalation: false
    capabilities:
        drop:
            - ALL
    privileged: false
    runAsNonRoot: true
{{ end }}
{{ end }}