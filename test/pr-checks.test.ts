// SPDX-License-Identifier: Apache-2.0
// .github/scripts/pr-checks.sh, the guard of release.yml and publish.yml that a tagged commit
// came from one merged pull request whose checks all passed (RELEASING.md). A fake gh on PATH
// answers with FAKE_HEADS (gh pr list) and FAKE_RUNS (gh api).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { after, test } from 'node:test';

const script = resolve(import.meta.dirname, '../.github/scripts/pr-checks.sh');
const dir = mkdtempSync(join(tmpdir(), 'pr-checks-'));
after(() => rmSync(dir, { recursive: true, force: true }));

writeFileSync(
	join(dir, 'gh'),
	'#!/usr/bin/env bash\ncase "$1" in pr) printf "%s" "$FAKE_HEADS" ;; api) printf "%s" "$FAKE_RUNS" ;; *) exit 2 ;; esac\n'
);
chmodSync(join(dir, 'gh'), 0o755);

const required = ['Type check and tests', 'Conformance (', 'Fuzz ('];
const passed = [
	'completed|success|Type check and tests',
	'completed|success|Conformance (process)',
	'completed|success|Fuzz (short)'
];

function run(heads: string, runs: string[]) {
	return spawnSync('bash', [script, 'main', 'c0ffee', ...required], {
		env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, GITHUB_REPOSITORY: 'o/r', FAKE_HEADS: heads, FAKE_RUNS: runs.join('\n') },
		encoding: 'utf8'
	});
}

test('passes when one pull request has every required check passed', () => {
	assert.equal(run('head1\n', passed).status, 0);
});

test('accepts skipped and neutral checks', () => {
	assert.equal(run('head1\n', [...passed, 'completed|skipped|Fuzz (long)', 'completed|neutral|Report']).status, 0);
});

test('refuses a commit that came from no pull request', () => {
	const r = run('', passed);
	assert.notEqual(r.status, 0);
	assert.match(r.stdout + r.stderr, /did not come from exactly one merged pull request/);
});

test('refuses a commit that came from two pull requests', () => {
	assert.notEqual(run('head1\nhead2\n', passed).status, 0);
});

test('refuses when a required check did not run', () => {
	const r = run('head1\n', passed.slice(0, 2));
	assert.notEqual(r.status, 0);
	assert.match(r.stdout + r.stderr, /check 'Fuzz \(' did not run/);
});

test('refuses when a check failed or is still running', () => {
	assert.notEqual(run('head1\n', [...passed, 'completed|failure|Lint']).status, 0);
	assert.notEqual(run('head1\n', [...passed, 'in_progress||Lint']).status, 0);
});
