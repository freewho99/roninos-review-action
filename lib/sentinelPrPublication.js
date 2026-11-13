// SENTINEL-RUNTIME-PR-PUBLICATION-1 — pure projection of canonical Sentinel
// observations for a pull-request check/comment. No collection, persistence,
// provider mutation, remediation, or merge-policy decision lives here.

export const SENTINEL_PR_PUBLICATION_MARKER = '<!-- opensoyce-sentinel-runtime-observation -->';
export const SENTINEL_PR_PUBLICATION_NONCLAIM =
  'Customer runtime observations are externally sourced and not independently verified. '
  + 'They do not establish a defect, root cause, severity, remediation, safety, approval, or merge decision. '
  + 'GitHub rulesets or branch protection separately control merge enforcement.';

const TOP_LEVEL_FIELDS = new Set([
  'ok', 'format', 'schema_version', 'input_identity', 'deterministic_observations',
  'inferred_advisories', 'runtime_observations', 'correlations', 'relationship_projection',
  'nodes', 'edges', 'coverage_gaps', 'limitations', 'provider_observation',
  'gate_precondition_state', 'non_claim',
]);
const SENTINEL_OBSERVATION_FORMAT = 'opensoyce-sentinel-observation';
const SENTINEL_OBSERVATION_VERSION = 1;
const FORBIDDEN_KEYS = new Set([
  'payload', 'sanitized_payload', 'prompt', 'messages', 'request_body', 'response_body',
  'sql', 'query', 'query_text', 'source_slice', 'explain_plan', 'plan_json', 'stack_trace',
]);
const SHA = /^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
const SHA256 = /^[a-f0-9]{64}$/i;
const MAX_RUNTIME_OBSERVATIONS = 100;
const MAX_RENDERED_OBSERVATIONS = 20;
const MAX_GAPS = 20;
const MAX_LIMITATIONS = 20;
const MAX_MARKDOWN = 60000;

function forbiddenPath(value, at = '$', seen = new Set()) {
  if (!value || typeof value !== 'object') return null;
  if (seen.has(value)) return `${at} (cyclic value)`;
  seen.add(value);
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_KEYS.has(String(key).toLowerCase())) return `${at}.${key}`;
    const nested = forbiddenPath(child, `${at}.${key}`, seen);
    if (nested) return nested;
  }
  seen.delete(value);
  return null;
}

function escapeMarkdown(value, max = 400) {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/[<>]/g, '')
    .replace(/[`|]/g, '\\$&')
    .trim()
    .slice(0, max);
}

function same(left, right) {
  return typeof left === 'string' && typeof right === 'string'
    && left.toLowerCase() === right.toLowerCase();
}

function unavailable(reasons, identity = null) {
  const unique = [...new Set(reasons)].sort();
  const markdown = [
    SENTINEL_PR_PUBLICATION_MARKER,
    '### Sentinel runtime observations — unavailable',
    '',
    ...unique.slice(0, MAX_GAPS).map((reason) => `- ${escapeMarkdown(reason, 800)}`),
    ...(unique.length > MAX_GAPS ? [`- ${unique.length - MAX_GAPS} additional reason(s) omitted by the publication bound.`] : []),
    '',
    `> ${SENTINEL_PR_PUBLICATION_NONCLAIM}`,
  ].join('\n');
  return { state: 'unavailable', identity, reasons: unique, observation_count: 0, markdown };
}

function comparisonLine(observation) {
  if (observation.kind === 'behavioral_postcondition') {
    return `expectation: ${escapeMarkdown(observation.facts?.expectation_state || 'not_supplied', 80)}`;
  }
  const comparison = observation.facts?.comparison;
  if (!comparison) return 'comparison: not_supplied';
  if (comparison.state !== 'comparable') {
    const reasons = Array.isArray(comparison.reasons) ? comparison.reasons.join(', ') : 'none recorded';
    return `comparison: ${escapeMarkdown(comparison.state, 80)} (${escapeMarkdown(reasons, 240)}); deltas: null`;
  }
  const deltas = comparison.deltas || {};
  const before = deltas.plan_transition?.before?.join(', ') || 'none';
  const after = deltas.plan_transition?.after?.join(', ') || 'none';
  return `comparison: comparable; rows examined Δ ${deltas.rows_examined}; rows returned Δ ${deltas.rows_returned}; duration Δ ${deltas.duration_ms} ms; ratio ${deltas.duration_ratio}; plan ${escapeMarkdown(before, 120)} → ${escapeMarkdown(after, 120)}`;
}

export function projectSentinelPrPublication(artifact, expectedIdentity) {
  if (artifact === undefined || artifact === null) return { state: 'absent', markdown: '', observation_count: 0, reasons: [] };
  const reasons = [];
  if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) {
    return unavailable(['INVALID_SENTINEL_ARTIFACT: expected an object']);
  }
  const unknown = Object.keys(artifact).filter((key) => !TOP_LEVEL_FIELDS.has(key));
  if (unknown.length > 0) reasons.push(`UNKNOWN_SENTINEL_ARTIFACT_FIELDS: ${unknown.sort().join(', ')}`);
  const forbidden = forbiddenPath(artifact);
  if (forbidden) reasons.push(`PAYLOAD_MINIMIZATION_REFUSAL: forbidden field at ${forbidden}`);
  if (artifact.format !== SENTINEL_OBSERVATION_FORMAT) reasons.push('FORMAT_MISMATCH');
  if (artifact.schema_version !== SENTINEL_OBSERVATION_VERSION) reasons.push('SCHEMA_VERSION_MISMATCH');
  if (artifact.ok !== true) reasons.push('ARTIFACT_NOT_ACCEPTED');

  const identity = artifact.input_identity;
  if (!identity || typeof identity !== 'object') {
    reasons.push('INPUT_IDENTITY_MISSING');
  } else {
    if (!identity.repository || !SHA.test(identity.base_sha || '') || !SHA.test(identity.head_sha || '') || !SHA256.test(identity.diff_sha256 || '')) {
      reasons.push('INPUT_IDENTITY_INVALID');
    }
    if (expectedIdentity?.repository && identity.repository !== expectedIdentity.repository) reasons.push('REPOSITORY_MISMATCH');
    if (!expectedIdentity?.repository) reasons.push('EXPECTED_REPOSITORY_IDENTITY_UNAVAILABLE');
    if (expectedIdentity?.base_sha && !same(identity.base_sha, expectedIdentity.base_sha)) reasons.push('BASE_SHA_MISMATCH');
    if (!expectedIdentity?.base_sha) reasons.push('EXPECTED_BASE_IDENTITY_UNAVAILABLE');
    if (expectedIdentity?.head_sha && !same(identity.head_sha, expectedIdentity.head_sha)) reasons.push('HEAD_SHA_MISMATCH');
    if (!expectedIdentity?.head_sha) reasons.push('EXPECTED_HEAD_IDENTITY_UNAVAILABLE');
    if (expectedIdentity?.diff_sha256 && !same(identity.diff_sha256, expectedIdentity.diff_sha256)) reasons.push('DIFF_SHA256_MISMATCH');
    if (!expectedIdentity?.diff_sha256) reasons.push('EXPECTED_DIFF_IDENTITY_UNAVAILABLE');
  }

  const observations = Array.isArray(artifact.runtime_observations) ? artifact.runtime_observations : [];
  if (!Array.isArray(artifact.runtime_observations)) reasons.push('RUNTIME_OBSERVATIONS_INVALID');
  if (observations.length > MAX_RUNTIME_OBSERVATIONS) reasons.push('RUNTIME_OBSERVATION_LIMIT_EXCEEDED');
  const nodes = Array.isArray(artifact.nodes) ? artifact.nodes : [];
  const references = nodes
    .flatMap((node) => Array.isArray(node?.evidence_refs) ? node.evidence_refs : [])
    .filter((ref) => ref?.provenance_kind === 'customer_runtime_observation');
  for (const ref of references) {
    if (ref.source_label !== 'externally_sourced' || ref.independently_verified !== false) {
      reasons.push(`RUNTIME_PROVENANCE_CEILING_VIOLATION: ${escapeMarkdown(ref.id || 'unknown', 140)}`);
    }
  }
  for (const observation of observations) {
    if (observation?.source_label !== 'externally_sourced' || observation?.independently_verified !== false) {
      reasons.push(`RUNTIME_OBSERVATION_PROVENANCE_VIOLATION: ${escapeMarkdown(observation?.observation_id || 'unknown', 140)}`);
    }
    const attached = nodes.some((node) =>
      Array.isArray(node?.facts?.runtime_observation_ids)
      && node.facts.runtime_observation_ids.includes(observation?.observation_id)
      && Array.isArray(node.evidence_refs)
      && node.evidence_refs.some((ref) => ref?.provenance_kind === 'customer_runtime_observation'));
    if (!attached) {
      reasons.push(`RUNTIME_SOURCE_ATTACHMENT_MISSING: ${escapeMarkdown(observation?.observation_id || 'unknown', 140)}`);
    }
  }
  if (reasons.length > 0) return unavailable(reasons, identity || null);

  const ordered = [...observations].sort((a, b) => String(a.observation_id).localeCompare(String(b.observation_id)));
  const lines = [
    SENTINEL_PR_PUBLICATION_MARKER,
    `### Sentinel runtime observations (${ordered.length})`,
    '',
    `Exact change: \`${escapeMarkdown(identity.repository, 200)}\` · base \`${identity.base_sha.slice(0, 12)}\` · head \`${identity.head_sha.slice(0, 12)}\` · diff \`${identity.diff_sha256.slice(0, 12)}\``,
    '',
  ];
  for (const observation of ordered.slice(0, MAX_RENDERED_OBSERVATIONS)) {
    lines.push(`- **${escapeMarkdown(observation.kind, 80)}** \`${escapeMarkdown(observation.observation_id, 140)}\` — ${comparisonLine(observation)}`);
    lines.push(`  - source: \`${escapeMarkdown(observation.source_binding?.path || 'unknown', 240)}\`; environment: \`${escapeMarkdown(observation.environment || 'unknown', 100)}\`; provenance: externally_sourced; independently verified: false`);
    const coverage = observation.coverage;
    if (coverage) lines.push(`  - coverage: ${escapeMarkdown(coverage.state || 'unknown', 80)}; missing facets: ${escapeMarkdown((coverage.missing_facets || []).join(', ') || 'none', 240)}`);
    for (const limitation of (observation.limitations || []).slice(0, 3)) lines.push(`  - limitation: ${escapeMarkdown(limitation, 400)}`);
  }
  if (ordered.length > MAX_RENDERED_OBSERVATIONS) {
    lines.push(`- ${ordered.length - MAX_RENDERED_OBSERVATIONS} additional observation(s) omitted by the publication bound.`);
  }
  const gaps = Array.isArray(artifact.coverage_gaps) ? artifact.coverage_gaps : [];
  const limitations = Array.isArray(artifact.limitations) ? artifact.limitations : [];
  if (gaps.length > 0) {
    lines.push('', '#### Recorded gaps', '', ...gaps.slice(0, MAX_GAPS).map((gap) => `- ${escapeMarkdown(gap, 500)}`));
    if (gaps.length > MAX_GAPS) lines.push(`- ${gaps.length - MAX_GAPS} additional gap(s) omitted by the publication bound.`);
  }
  if (limitations.length > 0) {
    lines.push('', '#### Limitations', '', ...limitations.slice(0, MAX_LIMITATIONS).map((item) => `- ${escapeMarkdown(item, 500)}`));
    if (limitations.length > MAX_LIMITATIONS) lines.push(`- ${limitations.length - MAX_LIMITATIONS} additional limitation(s) omitted by the publication bound.`);
  }
  lines.push('', `> ${SENTINEL_PR_PUBLICATION_NONCLAIM}`);
  let markdown = lines.join('\n');
  if (markdown.length > MAX_MARKDOWN) markdown = `${markdown.slice(0, MAX_MARKDOWN - 80)}\n\n...publication truncated at the bounded Markdown limit.`;
  return { state: 'observed', identity, reasons: [], observation_count: ordered.length, markdown };
}
