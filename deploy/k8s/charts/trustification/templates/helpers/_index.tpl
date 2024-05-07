{{/*
Sync interval for an index

Arguments (dict):
  * root - .
  * module - module object
  * storage - global storage configuration (.bombastic/.vexination)
*/}}
{{- define "trustification.index.syncInterval" }}
{{- (.module.index).syncInterval | default .storage.syncInterval | default .root.Values.index.syncInterval | default "1800s" }}
{{- end }}