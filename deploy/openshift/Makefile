.PHONY: template dashboards clean
CHART ?= ../k8s/chart
DASHBOARDS ?= ../k8s/dashboards

all: template dashboards

template:
	helm repo add guac https://kusaridev.github.io/helm-charts
	helm repo add keycloak https://charts.bitnami.com/bitnami
	helm dependency build $(CHART)
	helm template -f values.yaml --namespace '$${K8S_NAMESPACE}' trustification $(CHART) > generated.yaml
	cat generated.yaml | yq -e -y -s '{ apiVersion: "v1", kind: "Template", metadata: { name: "trustification" }, objects: . }' > template.yaml
	cat parameters.yaml >> template.yaml
	rm -f generated.yaml

dashboards:
	mkdir -p dashboards
	cp dashboard-base.yaml dashboards/dashboard.yaml
	for dashboard in $(DASHBOARDS)/*.json; do \
		name=$$(basename $$dashboard); \
        if [ "$$name" != "trustification-aws.json" ]; then \
			echo "  $$name: |" >> dashboards/dashboard.yaml; \
			cat $$dashboard | sed -e 's/^/    /' >> dashboards/dashboard.yaml; \
		fi; \
    done

clean:
	rm -f generated.yaml
	rm -f dashboard.yaml
