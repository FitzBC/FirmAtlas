# FirmAtlas repository instructions

## Definition of done

Every completed feature or bug fix must be deployed to the SSH host `satc_cloud`
before it is reported complete. This requirement applies across all Codex sessions.

For each change:

1. Implement and validate the change in the local environment first. Do not use
   `satc_cloud` as the primary development or debugging environment.
2. Run the relevant local backend tests, frontend tests, production frontend
   build, and local browser/API checks for the changed behavior.
3. Update `README.md` whenever the user-facing feature set, commands, data
   sources, or operating workflow changes.
4. Commit and push the intended revision.
5. Run `make deploy` from a clean worktree. Use `make deploy-with-data` only when
   the remote intelligence database must intentionally be replaced.
6. Verify the remote release revision, `/api/health`, the frontend document, and
   at least one endpoint covering the changed behavior.
7. Report the deployed Git revision and verification result. If deployment or
   verification fails, do not describe the feature as complete; report the blocker.

The canonical deployment procedure and recovery notes are in `deploy/README.md`.
Do not deploy over `/home/fitz/iot_firmwareassociation`; it is a different project.

## Firmware mapping research exception

The user has explicitly excluded the ongoing firmware communication-mapping
research track from SSH deployment. Changes whose scope is limited to
`firmatlas.mapping`, mapping research scripts/tests, and
`docs/firmware-mapping` must still be committed and pushed after full local
verification, but record SSH deployment as not applicable. This exception does
not apply to ordinary FirmAtlas product features or bug fixes.

When a mapping round reveals a non-trivial architecture split, dispatcher,
multi-process chain, misleading binary candidate, or obligation that changes
state after deeper analysis, evaluate it for the research casebook. Accepted
cases must preserve evidence references, the analysis-stage timeline,
counterfactual failure modes, limitations, and potential paper use. Do not
rewrite an earlier unresolved stage into a hindsight-only success narrative.
