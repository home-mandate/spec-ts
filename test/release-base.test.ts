// SPDX-License-Identifier: Apache-2.0
// .github/scripts/release-base.sh, the guard of release.yml and publish.yml that decides on
// which branch a tag may stand (RELEASING.md).
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { after, test } from 'node:test';

const script = resolve(import.meta.dirname, '../.github/scripts/release-base.sh');
const dir = mkdtempSync(join(tmpdir(), 'release-base-'));
after(() => rmSync(dir, { recursive: true, force: true }));

const env = { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.org', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.org' };
const git = (...args: string[]) => execFileSync('git', args, { cwd: dir, env, encoding: 'utf8' }).trim();

// root ── onMain, root ── onRelease01, root ── onRelease02, root ── elsewhere
git('init', '-q');
const tree = git('hash-object', '-t', 'tree', '-w', '/dev/null');
const root = git('commit-tree', tree, '-m', 'root');
const commits: Record<string, string> = { root };
for (const [name, branch] of [['onMain', 'main'], ['onRelease01', 'release/0.1'], ['onRelease02', 'release/0.2'], ['elsewhere', 'fix/other']] as const) {
  commits[name] = git('commit-tree', tree, '-p', root, '-m', name);
  git('update-ref', `refs/remotes/origin/${branch}`, commits[name] as string);
}

// null: refused.
const table: [string, string, string | null][] = [
  // A minor version comes from main only.
  ['v0.2.0', 'onMain', 'main'],
  ['v0.2.0-rc.1', 'onMain', 'main'],
  ['v0.2.0-alpha.1', 'onMain', 'main'],
  ['v0.1.0', 'onRelease01', null],
  ['v0.1.0-rc.2', 'onRelease01', null],
  // A patch comes from its own release branch only.
  ['v0.1.1', 'onRelease01', 'release/0.1'],
  ['v0.1.1-rc.1', 'onRelease01', 'release/0.1'],
  ['v0.1.10', 'onRelease01', 'release/0.1'],
  ['v0.2.3', 'onRelease02', 'release/0.2'],
  ['v0.1.1', 'onMain', null],
  ['v0.1.1-rc.1', 'onMain', null],
  // History the branches share.
  ['v0.2.0', 'root', 'main'],
  ['v0.1.1', 'root', 'release/0.1'],
  // Another release branch, one that does not exist, anywhere else.
  ['v0.1.2', 'onRelease02', null],
  ['v0.2.1', 'onRelease01', null],
  ['v0.3.1', 'onMain', null],
  ['v0.1.1', 'elsewhere', null],
  ['v0.2.0', 'elsewhere', null],
  // Not a version.
  ['v0.1', 'onMain', null],
  ['v0.2.0-beta.1', 'onMain', null],
  ['0.2.0', 'onMain', null],
  ['v0.2.0-rc.1;x', 'onMain', null],
  ['v0.2.0\nv0.2.1', 'onMain', null],
];

for (const [tag, commit, want] of table) {
  test(`${JSON.stringify(tag)} on ${commit}: ${want ?? 'refused'}`, () => {
    const run = spawnSync('bash', [script, tag, commits[commit] as string], { cwd: dir, encoding: 'utf8' });
    if (want === null) {
      assert.notEqual(run.status, 0);
      assert.equal(run.stdout.trim(), '');
      assert.match(run.stderr, /::error::/);
    } else {
      assert.equal(run.status, 0, run.stderr);
      assert.equal(run.stdout.trim(), want);
    }
  });
}
