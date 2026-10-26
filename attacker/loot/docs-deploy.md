# Deploy runbook

Steps to deploy payments-api to staging.

1. Merge to `main` and wait for the CI job to pass.
2. Check that the repo is reachable with the deploy token:

```bash
curl -s \
  -H "Authorization: token 42c627e12587324cfc0b4c2652e3fcd8dc154460" \
  http://gateway:8080/api/v1/repos/dev/payments-api
```

3. Run `npm run deploy:staging` and watch the logs.
4. If something breaks, ask in the platform channel.
