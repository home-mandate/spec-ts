# Releasing spec-ts

The rules are the same for the whole organization:
[RELEASING.md](https://github.com/home-mandate/.github/blob/main/RELEASING.md). This page says
only what is particular to this repository.

## What is published

The package `@home-mandate/spec` on npm, with provenance, and a GitHub release with the attested
conformance report. npm can't be taken back.

## Steps

1. A pull request sets `version` in `package.json`, and `homeMandateSpec` if the specification
   changed.
2. Tag the merge commit and push the tag. `release.yml` checks where the tag stands, that the
   pull request's checks passed and that the tag matches `version`, creates a draft release,
   attaches the attested conformance report (`conformance-report.yml`) and publishes the
   release only with the report attached. Then it starts `publish.yml`, which checks the tag
   again and publishes the package to npm.

A pre-release goes to the dist-tag `next`, anything else to `latest`. A published release is
immutable. When a run fails before the release is published, the draft stays and the version
needs a new tag (`-rc.N+1`). When only the npm publication fails, run `publish.yml` by hand on
the tag.

```sh
git switch main && git pull   # for a patch: release/X.Y
git tag -a v0.2.0-rc.1 -m "spec-ts v0.2.0-rc.1"
git push origin v0.2.0-rc.1
```
