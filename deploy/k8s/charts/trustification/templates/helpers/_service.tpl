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
  annotations:
    {{- if eq (include "trustification.openshift.useServiceCa" .root ) "true" }}
    service.beta.openshift.io/serving-cert-secret-name: {{ .name }}-tls
    {{- end }}
spec:
  ports:
  - name: endpoint
    port: {{ include "trustification.tls.http.port" (dict "root" .root "ingress" .module.ingress ) }}
    protocol: TCP
    targetPort: endpoint
  selector:
    {{- include "trustification.common.selectorLabels" . | nindent 4 }}
  type: ClusterIP
{{- end }}