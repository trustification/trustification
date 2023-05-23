# The madness of "image IDs"

The `PodStatus` section contains a list of containers, and the "image IDs". Which should carry the information
of which images actually run vs the image tags which are configured.

But actually, the format seems weird, and varies a lot:

| Image | Image Id | Where | Comment |
|-------|----------|-------|---------|
| `gcr.io/kubebuilder/kube-rbac-proxy:v0.8.0` | `gcr.io/kubebuilder/kube-rbac-proxy@sha256:34e8724e0f47e31eb2ec3279ac398b657db5f60f167426ee73138e2e84af6486` | OpenShift 4.12 | A classic example |
| `quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:39a74efe1cfaa84c93e5549a20dffaae990dbcc0203907f58bdeb24880956b04` | `quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:39a74efe1cfaa84c93e5549a20dffaae990dbcc0203907f58bdeb24880956b04` | OpenShift 4.12 | Example of using an image by SHA |
| `sha256:a329ae3c2c52fe00e9c4eaf48b081cd184ee4bf9aea059e497f4965f0a8deedb` | `docker.io/kindest/kindnetd:v20230330-48f316cd@sha256:c19d6362a6a928139820761475a38c24c0cf84d507b9ddf414a078cf627497af` | Kind 0.18.0 | Looks like image id and image are swapped, and the image only has the SHA digest, instead of the full name |
| `registry.k8s.io/coredns/coredns:v1.9.3` | `sha256:5185b96f0becf59032b8e3646e99f84d9655dff3ac9e2605e0dc77f9c441ae4a` | Kind 0.18.0 | Looks like a basic example, but shortened to SHA only |
| `registry.k8s.io/kube-apiserver:v1.26.3` | `docker.io/library/import-2023-03-30@sha256:ba097b515c8c40689733c0f19de377e9bf8995964b7d7150c2045f3dfd166657` | Kind 0.18.0 | Again a basic case, but with some random "import" image |
