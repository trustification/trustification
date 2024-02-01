{{/*
Default application image

Arguments (dict):
  * root - .
  * imageName - (optional) the base name of the image (defaults to "trust")
  * module - module object
*/}}
{{- define "trustification.common.defaultImage" }}
{{- include "trustification.common.image" ( dict "root" .root "image" .module.image "imageName" .imageName "defaults" .root.Values.image )}}
{{- end }}

{{/*
Common image specification.

Arguments (dict):
  * root - .
  * imageName - (optional) the base name of the image
  * defaults - (optional) image defaults (defaults to .Values.image)
  * image - image object
*/}}
{{- define "trustification.common.image" -}}
{{ $next := merge (deepCopy .) (dict "defaults" .root.Values.image ) }}
image: {{ include "trustification.common.imageName" $next }}
imagePullPolicy: {{ include "trustification.common.imagePullPolicy" $next }}
{{- end }}

{{/*
Image name

Arguments (dict):
  * root - .
  * imageName - (optional) the base name of the image
  * defaults - image defaults
  * image - image object
*/}}
{{- define "trustification.common.imageName" }}
{{- with .image.fullName }}
{{- . }}
{{- else }}
{{- include "trustification.common.imageRegistry" . }}/{{ .image.name | default .imageName | default .defaults.name | default "trust" }}:{{ include "trustification.common.imageVersion" . }}
{{- end }}
{{- end }}

{{/*
Image registry

Arguments (dict):
  * root - .
  * image - image object
  * defaults - image defaults
*/}}
{{ define "trustification.common.imageRegistry" }}{{ .image.registry | default .defaults.registry | default "quay.io/trustification" }}{{ end }}

{{/*
Image version

Arguments (dict):
  * root - .
  * module - module object
  * defaults - image defaults
*/}}
{{ define "trustification.common.imageVersion" }}{{ .image.version | default .defaults.version | default .root.Chart.AppVersion }}{{ end }}

{{/*
Image name

Arguments (dict):
  * root - .
  * image - image object
  * defaults - image defaults
*/}}
{{- define "trustification.common.imagePullPolicy" }}
{{- .image.pullPolicy | default .defaults.pullPolicy | default .defaults.pullPolicy }}
{{- end }}

