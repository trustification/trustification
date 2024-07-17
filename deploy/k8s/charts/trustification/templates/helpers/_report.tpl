{{/*
Volume mounts for the report authentication configuration.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.report.auth.volumeMount" }}
{{- if (.root.Values.report.auth) }}
- name: config-auth
  mountPath: /etc/nginx/.htpasswd
{{- if (.root.Values.report.auth.secretRef).key }}
  subPath: {{ .root.Values.report.auth.secretRef.key }}
{{- else }}
  subPath: .htpasswd
{{- end }}
  readOnly: true
{{- end }}
{{- end }}

{{/*
Volume for the report authentication configuration.

Arguments (dict):
  * root - .
  * name - name of the service
  * module - module object
*/}}
{{- define "trustification.report.auth.volume" }}
{{- if (.root.Values.report.auth) }}
- name: config-auth
  secret:
{{- if (.root.Values.report.auth).secretRef }}
    secretName: {{ .root.Values.report.auth.secretRef.name }}
{{- else }}
    secretName: {{ include "trustification.common.name" (set (deepCopy .) "name" (printf "%s-auth" .name ) ) }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Volume mounts for the report nginx server configuration.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.report.config.volumeMount" }}
- name: config-server
  mountPath: /etc/nginx/nginx.conf
  subPath: nginx.conf
  readOnly: true
{{- end }}

{{/*
Volume for the report nginx server configuration.

Arguments (dict):
  * root - .
  * name - name of the service
  * module - module object
*/}}
{{- define "trustification.report.config.volume" }}
- name: config-server
  configMap:
    name: {{ include "trustification.common.name" (set (deepCopy .) "name" (printf "%s-nginx-config" .name ) ) }}
{{- end }}

{{/*
Volume mounts for the report nginx server configuration.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.report.data.volumeMount" }}
- name: config-data
  mountPath: /opt/app-root/src
{{- end }}

{{/*
Volume for the report nginx server configuration.

Arguments (dict):
  * root - .
  * name - name of the service
  * module - module object
*/}}
{{- define "trustification.report.data.volume" }}
- name: config-data
  persistentVolumeClaim:
    claimName: {{ include "trustification.common.name" . }}
{{- end }}