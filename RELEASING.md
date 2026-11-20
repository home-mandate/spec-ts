# Releasing spec-ts

The rules are the same for the whole organization:
[RELEASING.md](https://github.com/home-mandate/.github/blob/main/RELEASING.md). This page says
only what is particular to this repository.

## What is published

The package `@home-mandate/spec` on npm, with provenance, and a GitHub release with the attested
conformance report. npm can't be taken back.

## Steps

`package.json` carries the version without a suffix. The jobs that build a release candidate
set `X.Y.Z-rc.N` from the tag before they build, test and pack, so a release candidate needs no
pull request, and the version is the commit of a release candidate.

1. A pull request sets `version` in `package.json` to `X.Y.Z`, and `homeMandateSpec` if the
   specification changed. `release/X.Y` starts from its commit.
2. Tag the release candidate on `release/X.Y` and push the tag. `release.yml` checks the tag
   (where it stands, that the pull request's checks passed, that it matches `version`),
   creates a draft release, attaches the attested conformance report
   (`conformance-report.yml`) and publishes the release only with the report attached. Then it
   starts `publish.yml`, which checks the tag again and publishes the package to npm.
3. The release gate follows: every fuzz target for 20 minutes, and `mandate-conformance`
   against the package installed from npm. The job `Release gate` succeeds only if all of it
   passed.
4. Tag the version on the commit of a release candidate whose gate passed.

While the specification itself is a release candidate, `homeMandateSpec` names that release
candidate and this package publishes release candidates against it. A version must name a
version: when the specification's version is out, a pull request moves `homeMandateSpec` to
it, a new release candidate follows, and the version goes on its commit. `release.yml` refuses
a version that names a release candidate of the specification.

A pre-release goes to the dist-tag `next`, anything else to `latest`. A published release is
immutable. When a run fails before the release is published, the draft stays and the version
needs a new tag (`-rc.N+1`). When only the npm publication fails, run `publish.yml` by hand on
the tag.

```sh
# the release candidate, on the release branch
gh workflow run release.yml --ref release/0.3 -f tag=v0.3.0-rc.1   # dry run, publishes nothing
git switch release/0.3 && git pull
git tag -a v0.3.0-rc.1 -m "spec-ts v0.3.0-rc.1"
git push origin v0.3.0-rc.1

# the version, on the commit of the release candidate, after its gate
gh workflow run release.yml --ref release/0.3 -f tag=v0.3.0
git tag -a v0.3.0 -m "spec-ts v0.3.0" v0.3.0-rc.1^{commit}
git push origin v0.3.0
```
