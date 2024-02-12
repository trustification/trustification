## SPoG UI branding

In order to brand the console using this Helm chart, you need to:

* Put all branding assets in the `files/branding` directory
* Edit the `files/spog-ui.yaml` file according to your needs

Then install the branding chart using Helm into the same namespace as you installed Trustification.

Ensure that the following values are configured in the Trustification values files, and apply them using `helm update`:

```yaml
modules:

  spogApi:
    uiConfiguration:
      configMapRef:
        name: spog-ui-config
        key: spog-ui.yaml

  spogUi:
    brandingConfigMap: spog-ui-branding

```
