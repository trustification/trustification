{{/*
Common labels

Arguments (dict):
  * root - .
  * name - name of the resource
  * component - component this resource belongs to
*/}}
{{ define "trustification.common.labels" }}
{{- include "trustification.common.selectorLabels" . }}
{{- if .root.Chart.AppVersion }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
app.kubernetes.io/part-of: {{ .root.Values.partOf | quote }}
{{ end }}

{{/*
Selector labels

Arguments (dict):
 * root - .
 * name - name of the resource
 * component - component this resource belongs to
*/}}
{{- define "trustification.common.selectorLabels" -}}
app.kubernetes.io/name: {{ .name }}
{{- with .component }}
app.kubernetes.io/component: {{ . }}
{{- end }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
{{- end }}
