#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# pr-checks.sh BASE COMMIT CHECK... refuses unless COMMIT came from exactly one merged pull
# request into BASE whose checks all passed, among them every CHECK (a prefix of a check's
# name). The branches take squash-merged pull requests; their checks ran on the pull request's
# head. Needs GH_TOKEN with pull-requests: read and checks: read. Used by release.yml and
# publish.yml.
set -euo pipefail

base=$1
commit=$2
shift 2

heads=$(gh pr list --repo "$GITHUB_REPOSITORY" --base "$base" --state merged --limit 200 \
  --json headRefOid,mergeCommit \
  --jq "[.[] | select(.mergeCommit.oid == \"$commit\") | .headRefOid] | unique | .[]")
if [ "$(printf '%s\n' "$heads" | grep -c .)" != 1 ]; then
  echo "::error::$commit did not come from exactly one merged pull request into $base"; exit 1
fi
runs=$(gh api "repos/$GITHUB_REPOSITORY/commits/$heads/check-runs?per_page=100" \
  --jq '.check_runs[] | "\(.status)|\(.conclusion)|\(.name)"')
printf '%s\n' "$runs"
for required in "$@"; do
  grep -qF "|$required" <<< "$runs" || { echo "::error::check '$required' did not run"; exit 1; }
done
if grep -vE '^completed\|(success|skipped|neutral)\|' <<< "$runs"; then
  echo "::error::not every check of the pull request passed"; exit 1
fi
