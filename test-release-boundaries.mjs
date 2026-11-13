import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { readSentinelArtifact, upsertCheckRun } from './post-review.mjs';

const hash = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
assert.equal(
  hash('lib/sentinelPrPublication.js'),
  '0f08c98dd1c963df1d53cc3e821821d039285da27f32cf280715d8bb9e99bb2f',
  'standalone projector must match the reviewed OpenSoyce source bytes',
);

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'roninos-review-release-'));
try {
  const valid = path.join(temp, 'sentinel.json');
  fs.writeFileSync(valid, JSON.stringify({ ok: true }));
  assert.deepEqual(readSentinelArtifact('sentinel.json', temp), { ok: true });
  assert.throws(() => readSentinelArtifact('../outside.json', temp), /SENTINEL_ARTIFACT_PATH_OUTSIDE_WORKSPACE/);

  const oversized = path.join(temp, 'oversized.json');
  fs.writeFileSync(oversized, Buffer.alloc((2 * 1024 * 1024) + 1));
  assert.throws(() => readSentinelArtifact('oversized.json', temp), /SENTINEL_ARTIFACT_TOO_LARGE/);

  const target = path.join(temp, 'target.json');
  const link = path.join(temp, 'link.json');
  fs.writeFileSync(target, '{}');
  try {
    fs.symlinkSync(target, link);
    assert.throws(() => readSentinelArtifact('link.json', temp), /SENTINEL_ARTIFACT_NOT_REGULAR_FILE/);
  } catch (error) {
    if (error?.code !== 'EPERM') throw error;
  }
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}

const calls = [];
const fetchImpl = async (url, init = {}) => {
  calls.push({ url, init, body: init.body ? JSON.parse(init.body) : null });
  if ((init.method || 'GET') === 'GET') {
    return { ok: true, status: 200, text: async () => JSON.stringify({ check_runs: [] }) };
  }
  return { ok: true, status: 201, text: async () => JSON.stringify({ id: 1 }) };
};

await upsertCheckRun({
  fetchImpl,
  token: 'fixture-token',
  repo: 'freewho99/fixture',
  headSha: '1'.repeat(40),
  conclusion: 'success',
  title: 'Bounded summary fixture',
  summary: 'x'.repeat(70_000),
});
const create = calls.find((call) => call.init.method === 'POST');
assert.equal(create.body.output.summary.length, 65_535);
assert.match(create.body.output.summary, /truncated at the GitHub character limit/);

const action = fs.readFileSync('action.yml', 'utf8');
assert.match(action, /sentinel-observation-path:/);
assert.match(action, /SENTINEL_ARGS=\(\)/);
assert.match(action, /"\$\{SENTINEL_ARGS\[@\]\}"/);

console.log('PASS standalone release boundaries: parity, containment, size, symlink, summary bound, optional action input');
