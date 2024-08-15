{{/*
Volume mounts for the user preferences configuration.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.preferences.db.volumeMount" }}
- name: user-preferences-db-path
  mountPath: /data/db/
{{- end }}


{{/*
Volume for the user preferences data.

*/}}
{{- define "trustification.preferences.db.volume" }}
- name: user-preferences-db-path
  persistentVolumeClaim:
    claimName: user-preferences-db-path
{{- end }}

{{/*
db path

*/}}
{{- define "trustification.preferences.db.path" }}
/data/db/
{{- end }}