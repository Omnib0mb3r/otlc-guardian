<!--
Thanks for opening a PR. Please fill in the sections below.
For security vulnerabilities, see SECURITY.md — do not open a public PR.
-->

## Summary

<!-- One or two sentences explaining what this changes and why. -->

## Type of change

- [ ] New injection / secret / audit pattern
- [ ] Bug fix
- [ ] New feature or CLI command
- [ ] Documentation
- [ ] Test coverage
- [ ] Refactor (no behavior change)
- [ ] Other (describe below)

## Checklist

- [ ] `npm test` passes locally (all 90 tests)
- [ ] `guardian check` passes locally
- [ ] `guardian audit . --fail-on-error` passes locally
- [ ] If I added a new pattern, it has BOTH a "must block" AND "must not fire" test
- [ ] If I added an entry to `security/.audit-allowlist`, it has a `reason: ...` field
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] No new dependencies added (Guardian is intentionally zero-dependency)
- [ ] No AI co-author tags in commit messages

## Test plan

<!-- How did you verify this change works? -->

## Related issues

<!-- Closes #123, related to #456, etc. -->
