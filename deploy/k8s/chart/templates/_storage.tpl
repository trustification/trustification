{{/* Environment variables required to configure the S3 storage */}}}
{{ define "trustification.storage-env" -}}

- name: STORAGE_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: "{{ .config.credentials }}"
      key: aws_access_key_id
- name: STORAGE_SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: "{{ .config.credentials }}"
      key: aws_secret_access_key

- name: STORAGE_BUCKET
  value: "{{ .config.bucket }}"

{{ with .config.storageEndpoint }}
- name: STORAGE_ENDPOINT
  value: "{{ .config.endpoint }}"
{{ end }}

{{ if .root.Values.deployMinio }}
- name: STORAGE_ENDPOINT
  value: "http://minio.{{ .root.Release.Namespace}}.svc.cluster.local:9000"
- name: STORAGE_REGION
  value: "eu-west-1"
{{ else }}
- name: STORAGE_REGION
  value: "{{ .root.Values.region }}"
{{ end }}


{{- end }}
