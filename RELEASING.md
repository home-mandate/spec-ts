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
2. Tag the merge commit and push the tag. A tag alone publishes nothing.
3. Publish a GitHub release for the tag. This starts `publish.yml`, which first checks where the
   tag stands and that the pull request's checks passed, and `conformance-report.yml`.

A pre-release goes to the dist-tag `next`, anything else to `latest`.

```sh
git switch main && git pull   # for a patch: release/X.Y
git tag -a v0.2.0-rc.1 -m "spec-ts v0.2.0-rc.1"
git push origin v0.2.0-rc.1
gh release create v0.2.0-rc.1 --verify-tag --prerelease --generate-notes
```
