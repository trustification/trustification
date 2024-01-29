{{/*
Default GUAC image

Arguments (dict):
  * root - .
  * imageName - (optional) the base name of the image
  * module - module object
*/}}
{{- define "trustification.guac.defaultImage" }}
{{- include "trustification.common.image" ( dict "root" .root "image" .module.image "imageName" .imageName "defaults" .root.Values.guac.image )}}
{{- end }}
