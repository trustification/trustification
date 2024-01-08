# SSO Postgres

For names, it may be necessary to replace `prod` with `staging`. It may also be required to change the project
first. Or apply `-n` arguments to all `oc` commands.

## Connect to the database

```shell
oc exec -it trustification-prod-postgresql-0 -- bash -c 'env PGPASSWORD=$POSTGRES_PASSWORD psql -U $POSTGRES_USER -d $POSTGRES_DATABASE'
```

## Reset the Postgres password of the Keycloak user

* Log in to the postgres database
* Get the current password by executing:
  
  ```shell
  oc get secrets sso-postgres -o json | jq -r .data.password | base64 -d
  ```

* Execute the following SQL command:
  
  ```sql
  ALTER USER bn_keycloak WITH PASSWORD 'new_password';
  ```

## Reset the Keycloak master admin user

* Log in to the postgres database
* Execute the following SQL command:
  
  ```sql
  BEGIN;
  DELETE FROM user_role_mapping WHERE user_id IN ( SELECT id FROM user_entity WHERE username='admin' );
  DELETE FROM credential WHERE user_id IN ( SELECT id FROM user_entity WHERE username='admin' );
  DELETE FROM user_entity WHERE username='admin';
  COMMIT;
  ```

* Restart the Keycloak pod
