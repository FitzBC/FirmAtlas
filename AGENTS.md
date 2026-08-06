# FirmAtlas repository instructions

## Definition of done

Every completed feature or bug fix must be deployed to the SSH host `satc_cloud`
before it is reported complete. This requirement applies across all Codex sessions.

For each change:

1. Run the relevant backend tests, frontend tests, and production frontend build.
2. Commit and push the intended revision.
3. Run `make deploy` from a clean worktree. Use `make deploy-with-data` only when
   the remote intelligence database must intentionally be replaced.
4. Verify the remote release revision, `/api/health`, the frontend document, and
   at least one endpoint covering the changed behavior.
5. Report the deployed Git revision and verification result. If deployment or
   verification fails, do not describe the feature as complete; report the blocker.

The canonical deployment procedure and recovery notes are in `deploy/README.md`.
Do not deploy over `/home/fitz/iot_firmwareassociation`; it is a different project.
