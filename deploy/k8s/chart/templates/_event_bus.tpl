{{/* Environment variables required to configure the S3 storage */}}}
{{ define "trustification.event-bus-env" -}}

{{ if .root.Values.deployKafka }}

- name: EVENT_BUS
  value: kafka

- name: KAFKA_BOOTSTRAP_SERVERS
  value: kafka.{{ .root.Release.Namespace}}.svc.cluster.local:9094

{{ else }}

- name: EVENT_BUS
  value: sqs

- name: SQS_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: "{{ .config.credentials }}"
      key: aws_access_key_id
- name: SQS_SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: "{{ .config.credentials }}"
      key: aws_secret_access_key
- name: SQS_REGION
  value: "{{ .root.Values.region }}"

{{ end }}

{{ end }}