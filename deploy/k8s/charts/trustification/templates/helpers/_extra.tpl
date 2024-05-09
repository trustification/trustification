{{/*
Additional volumes

Arguments (dict):
  * root - .
*/}}
{{- define "trustification.application.extraVolumes" }}
{{- with .root.Values.extraVolumes }}
{{- . | toYaml }}
{{- end }}
{{- end }}

{{/*
Additional volume mounts

Arguments (dict):
  * root - .
*/}}
{{- define "trustification.application.extraVolumeMounts" }}
{{- with .root.Values.extraVolumeMounts }}
{{- . | toYaml }}
{{- end }}
{{- end }}