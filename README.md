# sshpiper-plugins

## Tests

Regular tests can be run with:

```
go test ./...
```

End-to-end tests are tagged with `e2e` and run per plugin. For the database plugin:

```
docker compose -f database/compose.yaml up --abort-on-container-exit --exit-code-from testrunner
docker compose -f database/compose.yaml down -v # cleanup
```
