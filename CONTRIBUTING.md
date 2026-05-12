# Contributing

## Branch model

Two long-lived branches. Everything else is short-lived.

| Branch | Role |
|---|---|
| `main` | Released. Every commit on `main` is a tagged release (`vX.Y.Z`). Protected, only updated via PR from `develop`. |
| `develop` | Integration. All feature/fix work targets this branch. CI runs full test suite on every PR. |

Tags (`v0.1.0` … `vX.Y.Z`) live on `main` and are the canonical release markers. No `release/*` branches.

## Branch naming

Short-lived branches are cut from `develop` and named with a type prefix and a short noun:

| Prefix | Use for |
|---|---|
| `feat/` | New functionality |
| `fix/` | Bug fix |
| `chore/` | Dependencies, tooling, non-functional housekeeping |
| `refactor/` | Restructure with no behaviour change |
| `docs/` | Documentation only |
| `perf/` | Performance improvement |
| `test/` | Test-only changes |

Examples: `feat/org-scoped-users`, `fix/opa-cache-invalidation`, `chore/upgrade-fastify`, `refactor/user-groups-helper`.

**Don't** create branches named after a person (`jane/wip`), a sprint (`q2-2026`), or a vague theme (`improvements`). Don't add suffixes (`-v2`, `-new`, `-actual`) — rebase or rename instead.

## Lifecycle

1. **Branch** off latest `develop`:
   ```
   git checkout develop && git pull --ff-only
   git checkout -b feat/<short-noun>
   ```
2. **Work**: commit early, push often. Don't merge `develop` into your branch — rebase instead so history stays linear.
3. **PR**: open a PR targeting `develop`. Apply at least one type label (`feature`, `fix`, `chore`, `refactors`, `docs`, `perf`, `tests`) plus a semver label (`major` / `minor` / `patch`). The `enforce-label` CI check blocks merge without these.
4. **Review**: address feedback in additional commits (no force-push during review unless asked). Once approved, squash-merge into `develop`.
5. **Auto-delete**: branch deletion happens automatically on merge (repo setting). Locally: `git branch -d feat/<short-noun>`.

Releases:
1. Open a PR from `develop` to `main`.
2. After merge, tag `main` with `vX.Y.Z` following semver. The PR labels determine the bump:
   - `major` → `X+1.0.0`
   - `minor` → `X.Y+1.0`
   - `patch` → `X.Y.Z+1`
3. CI cuts a GitHub release and a Docker image tag from `vX.Y.Z`.

## Commit messages

Conventional Commits:
```
type(scope): subject

optional body explaining the WHY, not the what.
```

Subject ≤ 72 chars, imperative mood (`add`, `fix`, `remove`, not `added` / `adds`). Body only when the reason isn't obvious from the diff. No tool-attribution trailers.

Examples:
```
feat(org): org-scoped group management + permission middleware
fix(opa): retry datasource push when opal-server returns 503
refactor(user-groups): extract shared applyGroupUpdate helper; fail-closed identity
```

## What goes into a PR

- One logical change per PR. If the PR description has to say "also", split it.
- New code carries tests. Bugfix PRs add a failing-then-passing test.
- `npm run typecheck && npm test && npm run lint` clean locally before pushing.
- PR description states what changed, why, and any behaviour-visible deltas (status code changes, response shape changes, removed env vars).

## What does NOT get a branch

- Single-commit typo fix in a comment — commit directly to `develop` if you have write access.
- Generated files (lockfiles after `npm install`) — let dependabot own those PRs.

## Hygiene

- `git fetch --prune` regularly.
- A branch with no commits in 30 days and no open PR is stale. Either resume it (rebase on `develop`) or delete it.
- Don't keep dead branches "in case we need it later" — git tags and reflog cover that.
