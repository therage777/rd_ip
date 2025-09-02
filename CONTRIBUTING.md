# Contributing / Update Policy

This repository uses a direct-to-main workflow for routine updates.

## Update Policy

- Direct commits to `main`: For regular fixes, small features, and content/docs changes, commit directly to `main` and push without opening a PR.
- Commit style: Use concise, descriptive messages (Conventional Commits preferred, e.g., `feat: ...`, `fix: ...`, `docs: ...`).
- Scope: Keep changes focused and incremental. Split large work into multiple small commits.
- Reviews: Open PRs only when you explicitly want asynchronous review or for risky, multi-file refactors.
- Security-sensitive changes: If a change may impact authentication, authorization, secrets, or firewall behaviors, consider a short review (PR) despite the default policy.

## Commands (no PR)

```
# make your change(s)
git checkout main
git pull --ff-only
git add -A
git commit -m "feat: short description"
git push origin main
```

If you worked on a feature branch locally and want to follow the policy, fast-forward merge it locally, then push:

```
git checkout main
git pull --ff-only
git merge --ff-only your-branch
git push origin main
```

## Notes

- Ensure branch protection rules (if any) allow direct pushes to `main` for maintainers.
- CI/CD should run on `push` to `main`.
- Tag releases as needed for deploys or rollbacks.

