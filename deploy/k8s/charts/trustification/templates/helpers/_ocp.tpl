{{/*
Should the OpenShift CA be used, or not?

Arguments: .
*/}}
{{- define "trustification.openshift.useServiceCa" }}
{{- if eq ( include "trustification.openshift.detect" . ) "true" }}
{{- $.Values.openshift.useServiceCa }}
{{- else -}}
false
{{- end }}
{{- end }}

{{/*
Are we running on OpenShift?

Arguments: .
*/}}
{{- define "trustification.openshift.detect" }}
{{- if hasKey .Values.openshift "enabled" }}
{{- $.Values.openshift.enabled }}
{{- else -}}
{{ $.Capabilities.APIVersions.Has "route.openshift.io/v1/Route" }}
{{- end }}
{{- end }}
