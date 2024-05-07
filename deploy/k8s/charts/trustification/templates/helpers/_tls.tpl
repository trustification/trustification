{{/*
Evaluate the HTTP protocol (http, https).

Arguments: (dict)
  * root - .
*/}}
{{- define "trustification.tls.http.protocol" -}}
{{- if eq ( include "trustification.tls.serviceEnabled" .root ) "true" -}}
https
{{- else -}}
http
{{- end }}
{{- end }}

{{/*
Evaluate the HTTP port (80, 443).

Arguments: (dict)
  * root - .
*/}}
{{- define "trustification.tls.http.port" -}}
{{- if eq ( include "trustification.tls.serviceEnabled" .root ) "true" -}}
443
{{- else -}}
80
{{- end }}
{{- end }}

{{/*
Evaluate if services should be TLS enabled

Arguments: (dict)
  * . - .
*/}}
{{- define "trustification.tls.serviceEnabled" -}}
{{- include "trustification.openshift.useServiceCa" . }}
{{- end }}
