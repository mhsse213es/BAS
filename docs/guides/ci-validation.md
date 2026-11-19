# CI / CD validation gate

A build pipeline can ask Audspect to validate a piece of content on the factory lab agent and read back a verdict, so a
failing build stops the release. It uses a dedicated CI token, not a user login.

## What it does and does not do

- Starts one validation run for a content id (a scenario) on the factory lab agent and reports `pass`, `fail`,
  `no_data` or `error` when the run finishes. It uses the same rules as the validation lab.
- Needs a factory lab agent (`VALIDATION_LAB_AGENT_ID`). Without one every start request answers `503`.
- Validates the newest version of the content id. Retired or rejected content is refused.
- It does not run on production endpoints and does not publish or approve content.

## Issue a token (admin)

Needs the `ci:tokens:manage` permission, which only the admin role holds.

    curl -sk -X POST https://<host>:9543/api/ci-tokens \
      -H "Authorization: Bearer <admin session token>" \
      -d '{"name":"release pipeline"}'

The response carries `token` once. Store it in the pipeline's secret store; it cannot be read again. Only its SHA-256
is kept. `GET /api/ci-tokens` lists tokens (never secrets) with their last use; `DELETE /api/ci-tokens/{id}` revokes one
at once. Issuing and revoking are written to the audit log (`ci.token_created`, `ci.token_revoked`), as are starts
(`ci.validation_started`, `ci.validation_refused`), with the token as the actor (`ci:<token id>`).

A CI token opens `/api/ci/...` and nothing else, and a user session is refused on those routes.

## Start and wait

    RUN=$(curl -sk -X POST https://<host>:9543/api/ci/validations \
      -H "Authorization: Bearer $CI_TOKEN" -d '{"contentId":"my-scenario-id"}' | jq -r .runId)

    while :; do
      R=$(curl -sk https://<host>:9543/api/ci/validations/$RUN -H "Authorization: Bearer $CI_TOKEN")
      [ "$(echo "$R" | jq -r .state)" = completed ] && break
      sleep 15
    done
    [ "$(echo "$R" | jq -r .verdict)" = pass ]    # non-zero exit fails the pipeline

| Start response | Meaning |
| --- | --- |
| `202` + `runId` | Run started |
| `404` | No such content id |
| `409` + `reason` | The lab declined for now (agent busy or offline, content retired). Retry later |
| `503` | No factory lab agent is configured |

`no_data` means nothing ran (everything skipped or blocked by the lab environment). Treat it as not validated, not as a
pass. Poll with a time limit: a run that never completes is the pipeline's to give up on.
