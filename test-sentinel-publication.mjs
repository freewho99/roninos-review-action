import assert from 'node:assert/strict';
import { projectSentinelPrPublication } from './lib/sentinelPrPublication.js';

const SHA = {
  base: '1'.repeat(40), head: '2'.repeat(40), diff: '3'.repeat(64), artifact: '5'.repeat(64),
};
const identity = { repository: 'freewho99/opensoyce', base_sha: SHA.base, head_sha: SHA.head, diff_sha256: SHA.diff };

function observation(kind, id, facts) {
  return {
    kind,
    observation_id: id,
    observed_at: '2026-11-12T16:30:00.000Z',
    environment: 'customer-staging',
    collector: { control: 'customer_controlled', name: 'manual-fixture', version: '1.0.0' },
    source_binding: { path: 'src/worker.ts', symbol: 'runWork', commit_sha: SHA.head, artifact_digest: `sha256:${SHA.artifact}` },
    coverage: { expected_facets: ['actions'], instrumented_facets: ['actions'], missing_facets: [], state: 'complete' },
    facts,
    limitations: ['Caller-supplied instrumentation may be incomplete.'],
    source_label: 'externally_sourced',
    provenance_kind: 'customer_runtime_observation',
    independently_verified: false,
  };
}

function artifact(runtimeObservations) {
  return {
    ok: true,
    format: 'opensoyce-sentinel-observation',
    schema_version: 1,
    input_identity: identity,
    deterministic_observations: [],
    inferred_advisories: [],
    runtime_observations: runtimeObservations,
    correlations: [],
    relationship_projection: {},
    nodes: [{
      id: 'source:worker',
      facts: { runtime_observation_ids: runtimeObservations.map((item) => item.observation_id) },
      evidence_refs: runtimeObservations.map((item) => ({
        id: `runtime:${item.observation_id}`,
        provenance_kind: 'customer_runtime_observation',
        source_label: 'externally_sourced',
        independently_verified: false,
      })),
    }],
    edges: [],
    coverage_gaps: [],
    limitations: ['Point-in-time customer observation.'],
    provider_observation: null,
    gate_precondition_state: 'PRECONDITIONS_UNMET',
    non_claim: 'Observation only.',
  };
}

const expected = { ...identity };

const observed = projectSentinelPrPublication(artifact([
  observation('behavioral_postcondition', 'behavior-1', { expectation_state: 'expectation_observed' }),
]), expected);
assert.equal(observed.state, 'observed');
assert.match(observed.markdown, /expectation_observed/);

const notObserved = projectSentinelPrPublication(artifact([
  observation('behavioral_postcondition', 'behavior-0', { expectation_state: 'expectation_not_observed' }),
]), expected);
assert.equal(notObserved.state, 'observed');
assert.match(notObserved.markdown, /expectation_not_observed/);
assert.doesNotMatch(notObserved.markdown, /\b(defect found|root cause is|severity:|remediation required|merge blocked)\b/i);
assert.match(notObserved.markdown, /do not establish a defect, root cause, severity/);

const comparable = projectSentinelPrPublication(artifact([
  observation('database_execution_plan', 'db-comparable', {
    comparison: {
      state: 'comparable', reasons: [],
      deltas: {
        rows_examined: 2400, rows_returned: 0, duration_ms: 108.45, duration_ratio: 10,
        plan_transition: { before: ['Index Scan'], after: ['Filter', 'Seq Scan'] },
      },
    },
  }),
]), expected);
assert.match(comparable.markdown, /rows examined Δ 2400/);
assert.match(comparable.markdown, /Index Scan.*Filter, Seq Scan/);

const incompatible = projectSentinelPrPublication(artifact([
  observation('database_execution_plan', 'db-incompatible', {
    comparison: { state: 'comparison_not_valid', reasons: ['ENVIRONMENT_MISMATCH'], deltas: null },
  }),
]), expected);
assert.match(incompatible.markdown, /comparison_not_valid/);
assert.match(incompatible.markdown, /ENVIRONMENT_MISMATCH/);
assert.match(incompatible.markdown, /deltas: null/);

const stale = projectSentinelPrPublication(artifact([]), { ...expected, head_sha: '4'.repeat(40) });
assert.equal(stale.state, 'unavailable');
assert.deepEqual(stale.reasons, ['HEAD_SHA_MISMATCH']);
assert.match(stale.markdown, /unavailable/);
assert.doesNotMatch(stale.markdown, /clean|passed/i);

const raw = artifact([]);
raw.payload = { sql: 'select secret from customer' };
const rawResult = projectSentinelPrPublication(raw, expected);
assert.equal(rawResult.state, 'unavailable');
assert.ok(rawResult.reasons.some((reason) => reason.startsWith('PAYLOAD_MINIMIZATION_REFUSAL')));
assert.ok(rawResult.reasons.some((reason) => reason.startsWith('UNKNOWN_SENTINEL_ARTIFACT_FIELDS')));

const upgraded = artifact([observation('behavioral_postcondition', 'upgraded', { expectation_state: 'expectation_observed' })]);
upgraded.nodes[0].evidence_refs[0].independently_verified = true;
assert.ok(projectSentinelPrPublication(upgraded, expected).reasons.some((reason) => reason.startsWith('RUNTIME_PROVENANCE_CEILING_VIOLATION')));

const detached = artifact([observation('behavioral_postcondition', 'detached', { expectation_state: 'expectation_observed' })]);
detached.nodes[0].evidence_refs = [];
assert.ok(projectSentinelPrPublication(detached, expected).reasons.some((reason) => reason.startsWith('RUNTIME_SOURCE_ATTACHMENT_MISSING')));

const repeatA = projectSentinelPrPublication(comparable.state === 'observed' ? artifact([
  observation('database_execution_plan', 'db-comparable', { comparison: { state: 'comparison_not_valid', reasons: ['DATASET_MISMATCH'], deltas: null } }),
]) : null, expected);
const repeatB = projectSentinelPrPublication(artifact([
  observation('database_execution_plan', 'db-comparable', { comparison: { state: 'comparison_not_valid', reasons: ['DATASET_MISMATCH'], deltas: null } }),
]), expected);
assert.equal(repeatA.markdown, repeatB.markdown, 'projection must be deterministic');

assert.equal(projectSentinelPrPublication(null, expected).state, 'absent');

console.log('PASS Sentinel runtime PR publication: 4 fixtures, identity, provenance, minimization, attachment, determinism');
