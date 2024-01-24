{{/*
A default service declaration.

Arguments (dict):
  * root - .
  * name - the name of the service
  * module - module object
*/}}
{{ define "trustification.application.defaultService" }}
apiVersion: v1
kind: Service
metadata:
  name: {{ include "trustification.common.name" . }}
  labels:
    {{- include "trustification.common.labels" . | nindent 4 }}
spec:
  ports:
  - name: endpoint
    port: 8080
    protocol: TCP
    targetPort: 8080
  selector:
    {{- include "trustification.common.selectorLabels" . | nindent 4 }}
  type: ClusterIP
{{- end }}