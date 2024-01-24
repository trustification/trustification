{{/*
Image name

Arguments (dict):
  * root - .
  * imageName - the base name of the image
  * module - module object
*/}}
{{ define "trustification.common.image" }}
{{- with .module.imageOverride }}
{{- . }}
{{- else }}
{{- include "trustification.common.imageRegistry" . }}/{{ .imageName | default "trust" }}:{{ include "trustification.common.imageVersion" . }}
{{- end }}
{{- end }}

{{/*
Image registry

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{ define "trustification.common.imageRegistry" }}{{ .module.image.registry | default .root.Values.image.registry }}{{ end }}

{{/*
Image version

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{ define "trustification.common.imageVersion" }}{{ .module.image.version | default .root.Values.image.version | default .root.Chart.AppVersion }}{{ end }}

{{/*
Image name

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.common.imagePullPolicy" }}
{{- .module.image.pullPolicy | default .root.Values.image.pullPolicy }}
{{- end }}

