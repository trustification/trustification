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
Path where report data will be stored
*/}}
{{- define "trustification.report.data.path" -}}
/tmp/share/report
{{- end -}}


{{/*
Volume mounts for the report nginx server data.

Arguments (dict):
  * root - .
  * module - module object
*/}}
{{- define "trustification.report.data.volumeMount" }}
{{- if .root.Values.report.enabled }}
- name: report-data
  mountPath: {{ include "trustification.report.data.path" . }}
{{- end }}
{{- end }}

{{/*
Volume for the report nginx server data.

Arguments (dict):
  * root - .
  * name - name of the service
  * module - module object
*/}}
{{- define "trustification.report.data.volume" }}
{{- if .root.Values.report.enabled }}
- name: report-data
  persistentVolumeClaim:
    claimName: report-server
{{- end }}
{{- end }}

{{/*
Configuration for pod affinity of walker jobs.

Arguments (dict):
  * root - .
  * name - name of the service
  * module - module object
*/}}
{{- define "trustification.report.affinity" }}
{{- if .root.Values.report.enabled }}
affinity:
  podAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchExpressions:
            - key: report
              operator: In
              values:
                - server
        topologyKey: "kubernetes.io/hostname"
{{- end }}
{{- end }}

{{/*
Configuration for arguments of walker jobs.

Arguments (dict):
  * root - .
  * name - name of the service
  * module - module object
*/}}
{{- define "trustification.report.walkerArgs" }}
{{- if .root.Values.report.enabled }}
- "--report-enable"
- "true"
- "--report-path"
- {{ include "trustification.report.data.path" . | quote }}
{{- end }}
{{- end }}

{{/*
Configuration for inline arguments of walker jobs.

Arguments (dict):
  * root - .
  * name - name of the service
  * module - module object
*/}}
{{- define "trustification.report.walkerInlineArgs" -}}
{{- if .root.Values.report.enabled -}}
--report-enable true --report-path {{ include "trustification.report.data.path" . }}
{{- end -}}
{{- end -}}
