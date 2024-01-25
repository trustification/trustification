{{/*
Image

Arguments (dict):
  * root - .
  * imageName - the base name of the image (defaults to "trust")
  * image - image object
*/}}
{{- define "trustification.common.image" -}}
image: {{ include "trustification.common.imageName" . }}
imagePullPolicy: {{ include "trustification.common.imagePullPolicy" . }}
{{- end }}

{{/*
Default application image

Arguments (dict):
  * root - .
  * imageName - the base name of the image (defaults to "trust")
  * module - module object
*/}}
{{- define "trustification.common.defaultImage" }}
{{- include "trustification.common.image" ( dict "root" .root "image" .module.image "imageName" .imageName )}}
{{- end }}

{{/*
Image name

Arguments (dict):
  * root - .
  * imageName - the base name of the image
  * image - image object
*/}}
{{- define "trustification.common.imageName" }}
{{- with .image.fullName }}
{{- . }}
{{- else }}
{{- include "trustification.common.imageRegistry" . }}/{{ .imageName | default "trust" }}:{{ include "trustification.common.imageVersion" . }}
{{- end }}
{{- end }}

{{/*
Image registry

Arguments (dict):
  * root - .
  * image - image object
*/}}
{{ define "trustification.common.imageRegistry" }}{{ .image.registry | default .root.Values.image.registry | default "quay.io/trustification" }}{{ end }}

{{/*
Image version

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{ define "trustification.common.imageVersion" }}{{ .image.version | default .root.Values.image.version | default .root.Chart.AppVersion }}{{ end }}

{{/*
Image name

Arguments (dict):
  * root - .
  * image - image object
*/}}
{{- define "trustification.common.imagePullPolicy" }}
{{- .image.pullPolicy | default .root.Values.image.pullPolicy }}
{{- end }}

