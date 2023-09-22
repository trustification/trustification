# Managing the indices

For names, it may be necessary to replace `prod` with `staging`. It may also be required to change the project
first. Or apply `-n` arguments to all `oc` commands.

## Reset the index

* Delete the `index` file in the `bombastic-prod` and `vexination-prod` S3 buckets
* Restart the indexer pods
  
  ```shell
  oc delete pods -l app.kubernetes.io/component=indexer
  ```
