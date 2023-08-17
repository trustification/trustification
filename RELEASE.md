# Release process

A Trustification release consists of the `trust` binary along with SBOM, attestations and container images hosted on ghcr.io.

The release process is built around automation in GitHub Actions. The following GHA workflows are involved:

* `ci` - building and testing the source
* `release` - build release artifacts and metadata, also runs `container` and `staging` workflows. Publishes artifacts and containers.
* `containers` - builds container images.
* `staging` - triggers an update of https://staging.trustification.dev
* `nightly` - cron-job that tags a nightly release, which works like any regular release but with a special version.

## Creating a release

Follow these steps to create a release:

* Create a git tag
* Update Cargo.toml with 'next release' versions

NOTE: The last step is important to ensure nightly versions appear as being newer than the latest release.

### Create a git tag 

```shell
git tag 0.2.0 -m 'Tag new release'
git push --follow-tags
```


### Update Cargo.toml version

All Cargo.toml files in the repo needs updating.

Once updated, commit and push:

```shell
git add <list of Cargo.tomls>
git commit -m 'chore: update current version'
git push
```

## Updating the staging environment

The staging environment is automatically updated for any given release, which also means nightly releases will also update the staging environment automatically.

## Note on permissions

The pipelines mostly rely on standard builder tokens, but there are a few exceptions:

* NIGHTLY_TOKEN - this token is used by the nightly workflow to push the nightly tags. 
* STAGING_TOKEN - this token is used to trigger the workflows in the trustification.dev repository.
