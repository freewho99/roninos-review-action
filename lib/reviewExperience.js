const NON_CLAIMS = Object.freeze([
  'A deterministic pass means no modeled invariant failed; it is not approval or proof that no defect exists.',
  'A finding is a modeled observation or confirmed flow; it is not an exploitability proof.',
  'External evidence is reported context; it never becomes a RoninOS DENY without a modeled invariant or policy.'
]);

const HEX_SHA = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/i;

function short(value, max = 10) {
  const text = String(value || '');
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

function isResolvedSha(value) {
  return typeof value === 'string' && HEX_SHA.test(value);
}

function postureOf(receipt) {
  const failed = (receipt.checks || []).filter((check) => check.status === 'FAILED');
  const observed = (receipt.checks || []).filter((check) => check.status === 'OBSERVATION');
  if (failed.length > 0) return 'MODELED_VIOLATION';
  if (observed.length > 0) return 'OBSERVATIONS_ONLY';
  return 'NO_MODELED_VIOLATION';
}

function findingsOf(receipt) {
  return (receipt.checks || [])
    .filter((check) => check.status === 'FAILED' || check.status === 'OBSERVATION')
    .map((check) => ({
      ruleId: check.id || check.ruleId || 'UNKNOWN_RULE',
      status: check.status,
      tier: check.tier || null,
      file: check.file || null,
      line: check.line || null,
      cwe: check.cwe || null,
      bundleId: check.bundleId || null,
      details: check.details || check.message || '',
      patchVerified: check.patchVerified === true || check.patchStatus === 'PROVEN_COMPLIANT_BY_AST_AND_GATE'
    }));
}

function bundleIdsOf(receipt) {
  return [...new Set((receipt.bundleReceipts || []).map((bundle) => bundle.bundleId).filter(Boolean))].sort();
}

function filesOf(receipt) {
  const checks = receipt.checks || [];
  const bundles = receipt.bundleReceipts || [];
  return [...new Set([
    ...checks.map((check) => check.file).filter(Boolean),
    ...bundles.flatMap((bundle) => bundle.files || bundle.filePaths || [])
  ])].sort();
}

function proofCount(receipt) {
  return (receipt.checks || []).filter((check) =>
    check.patchVerified === true
    || check.patchStatus === 'PROVEN_COMPLIANT_BY_AST_AND_GATE'
    || check.proverGrade === 'PROVEN_COMPLIANT_BY_AST_AND_GATE'
  ).length;
}

export function buildPrSummary(receipt, options = {}) {
  const posture = postureOf(receipt);
  const findings = findingsOf(receipt);
  const failed = findings.filter((finding) => finding.status === 'FAILED');
  const observed = findings.filter((finding) => finding.status === 'OBSERVATION');
  const bundles = bundleIdsOf(receipt);
  const files = filesOf(receipt);
  const headSha = isResolvedSha(receipt.git?.headSha) ? receipt.git.headSha : null;
  const proof = proofCount(receipt);
  const title = options.title || 'RoninOS Review';
  const lines = [
    `## ${title}`,
    '',
    `**Gate posture:** \`${posture}\`  `,
    `**Head SHA:** ${headSha ? `\`${headSha}\`` : '`unavailable` (no resolved commit identity)'}  `,
    `**Bundles:** ${bundles.length} · **Changed files:** ${files.length} · **Findings:** ${failed.length} blocked, ${observed.length} observed · **Verified patches:** ${proof}`,
    ''
  ];

  if (failed.length > 0) {
    lines.push('### Blocked modeled findings', '', '| Rule | File | Line | CWE | Observation |', '|---|---|---:|---|---|');
    for (const finding of failed) {
      lines.push(`| \`${finding.ruleId}\` | \`${finding.file || 'unknown'}\` | ${finding.line || '—'} | ${finding.cwe || '—'} | ${String(finding.details).replace(/\|/g, '\\|')} |`);
    }
    lines.push('');
  }

  if (observed.length > 0) {
    lines.push('### Observations (non-blocking)', '', '| Rule | File | Details |', '|---|---|---|');
    for (const finding of observed) {
      lines.push(`| \`${finding.ruleId}\` | \`${finding.file || 'unknown'}\` | ${String(finding.details).replace(/\|/g, '\\|')} |`);
    }
    lines.push('');
  }

  if (findings.length === 0) {
    lines.push('No modeled invariant failed on this change. This is not approval and does not cover unmodeled defects.', '');
  }

  if (proof > 0) {
    lines.push(`### Proof`, '', `${proof} remediation patch(es) passed the closed-loop post-image gate.`, '');
  }

  if (files.length > 0) {
    lines.push('### Changed files', '', ...files.map((file) => `- \`${file}\``), '');
  }

  if (bundles.length > 0) {
    lines.push('### REA bundles', '', ...bundles.map((bundle) => `- \`${bundle}\``), '');
  }

  lines.push('---', ...NON_CLAIMS.map((claim) => `- ${claim}`));
  return {
    posture,
    headSha,
    markdown: lines.join('\n'),
    summary: {
      bundles: bundles.length,
      files: files.length,
      blocked: failed.length,
      observed: observed.length,
      verifiedPatches: proof
    },
    findings,
    bundleIds: bundles,
    nonClaims: NON_CLAIMS
  };
}

function citationsFor(receipt) {
  return {
    headSha: isResolvedSha(receipt.git?.headSha) ? receipt.git.headSha : null,
    bundles: bundleIdsOf(receipt),
    files: filesOf(receipt),
    receiptId: receipt.receiptId || receipt.receipt_id || null
  };
}

export function answerReviewQuestion(question, receipt) {
  const text = String(question || '').trim();
  const findings = findingsOf(receipt);
  const failed = findings.filter((finding) => finding.status === 'FAILED');
  const observed = findings.filter((finding) => finding.status === 'OBSERVATION');
  const bundles = bundleIdsOf(receipt);
  const files = filesOf(receipt);
  const citations = citationsFor(receipt);
  const posture = postureOf(receipt);

  const answer = (body, cites) => ({
    grounded: true,
    answer: body,
    citations: cites,
    posture,
    nonClaims: NON_CLAIMS
  });

  const refuse = () => ({
    grounded: false,
    answer: 'The receipt does not contain that information. This chat answers only from the supplied RoninOS receipt and evidence.',
    citations: [],
    posture,
    nonClaims: NON_CLAIMS
  });

  if (!text) return refuse();

  if (/\b(why|block|blocked|fail|failed|violation)\b/i.test(text)) {
    if (failed.length === 0) return answer('No modeled invariant failed in this receipt. That is not approval and does not cover unmodeled defects.', citations);
    return answer(
      `${failed.length} modeled finding(s) are in DENY posture: ${failed.map((finding) => `${finding.ruleId} at ${finding.file || 'unknown'}${finding.line ? `:${finding.line}` : ''}`).join('; ')}.`,
      failed.map((finding) => ({ ruleId: finding.ruleId, file: finding.file, line: finding.line, bundleId: finding.bundleId }))
    );
  }

  if (/\b(what changed|summary|change|files?|bundles?)\b/i.test(text)) {
    return answer(
      `${files.length} file(s) and ${bundles.length} REA bundle(s) are in this receipt.${files.length ? ` Files: ${files.join(', ')}.` : ''}${bundles.length ? ` Bundles: ${bundles.join(', ')}.` : ''}`,
      [{ files }, { bundles }]
    );
  }

  if (/\b(patch|fix|remediation|prover|proof)\b/i.test(text)) {
    const verified = findings.filter((finding) => finding.patchVerified);
    if (verified.length === 0) return answer('The receipt contains no verified remediation patch. This does not prove that no remediation exists.', citations);
    return answer(
      `${verified.length} patch(es) are marked verified by the closed-loop post-image gate: ${verified.map((finding) => finding.ruleId).join(', ')}.`,
      verified.map((finding) => ({ ruleId: finding.ruleId, file: finding.file, patchVerified: true }))
    );
  }

  if (/\b(observation|warn|warning|non-blocking)\b/i.test(text)) {
    return answer(
      observed.length
        ? `${observed.length} observation(s) are present and non-blocking: ${observed.map((finding) => finding.ruleId).join(', ')}.`
        : 'No observations are present in this receipt.',
      observed.map((finding) => ({ ruleId: finding.ruleId, file: finding.file }))
    );
  }

  if (/\b(rules?|rule ids?|which rule|what rule)\b/i.test(text)) {
    const rules = [...new Set(findings.map((finding) => finding.ruleId))];
    return answer(
      rules.length ? `Rules in this receipt: ${rules.join(', ')}.` : 'No modeled rule appears in this receipt.',
      [{ rules }]
    );
  }

  if (/\b(line|lines|where exactly|location|span)\b/i.test(text)) {
    const locations = findings.map((finding) => ({
      ruleId: finding.ruleId,
      file: finding.file,
      line: finding.line
    }));
    return answer(
      locations.length
        ? `Finding locations: ${locations.map((location) => `${location.ruleId} at ${location.file || 'unknown'}${location.line ? `:${location.line}` : ''}`).join('; ')}.`
        : 'No finding location is present in this receipt.',
      locations
    );
  }

  if (/\b(how many|count|number of)\b/i.test(text)) {
    return answer(
      `${findings.length} finding(s): ${failed.length} blocked and ${observed.length} observed; ${proofCount(receipt)} verified patch(es); ${bundles.length} bundle(s); ${files.length} file(s).`,
      [{ findings: findings.length, blocked: failed.length, observed: observed.length, verifiedPatches: proofCount(receipt), bundles: bundles.length, files: files.length }]
    );
  }

  if (/\b(what should i do|next step|next action|remediat|how do i fix)\b/i.test(text)) {
    if (failed.length === 0) {
      return answer('There is no blocked modeled finding in this receipt. Review observations separately; this is not approval.', citations);
    }
    return answer(
      'Review the blocked findings, then either apply a patch that passes the closed-loop post-image gate or record an explicit policy waiver. The receipt does not choose the business decision.',
      failed.map((finding) => ({ ruleId: finding.ruleId, file: finding.file, line: finding.line }))
    );
  }

  if (/\b(vulnerab|exploit|severity|impact)\b/i.test(text)) {
    return answer(
      `The receipt records ${posture} with ${failed.length} blocked and ${observed.length} observed finding(s). It does not prove exploitability or business impact.`,
      [{ posture, blocked: failed.length, observed: observed.length }]
    );
  }

  if (/\b(head|sha|receipt|bundle|evidence|custody)\b/i.test(text)) {
    return answer(
      `Head SHA: ${citations.headSha || 'unavailable'}. Bundle count: ${citations.bundles.length}. Receipt ID: ${citations.receiptId || 'not recorded'}.`,
      [citations]
    );
  }

  if (/\b(pre-existing|preexisting|net-new|net new|baseline)\b/i.test(text)) {
    return refuse();
  }

  if (/\b(safe|clean|approve|approved|compliant)\b/i.test(text)) {
    return answer(
      `The gate posture is ${posture}. This is not an approval, safety claim, or proof that no defect exists.`,
      [{ posture }]
    );
  }

  return refuse();
}

function allowedChatSymbols(receipt, answer) {
  const allowed = new Set([
    ...filesOf(receipt),
    ...bundleIdsOf(receipt),
    ...(receipt.checks || []).map((check) => check.id || check.ruleId).filter(Boolean),
    ...(receipt.checks || []).map((check) => check.cwe).filter(Boolean),
    receipt.git?.headSha,
    receipt.receiptId,
    receipt.receipt_id,
    postureOf(receipt),
    ...(answer.citations || []).flatMap((citation) => Object.values(citation).flat())
  ].filter(Boolean).map(String));
  return allowed;
}

function hasUngroundedBacktickSymbol(answer, allowed) {
  for (const match of String(answer || '').matchAll(/`([^`]+)`/g)) {
    const token = match[1].trim().split(/[\s:(]/)[0];
    if (!token) continue;
    if (allowed.has(token)) continue;
    if (allowed.has(token.replace(/[,.;]+$/, ''))) continue;
    return token;
  }
  return null;
}

export async function answerReviewQuestionWithModel(question, receipt, options = {}) {
  const deterministic = answerReviewQuestion(question, receipt);
  if (!deterministic.grounded) return { ...deterministic, phrasedBy: 'deterministic' };

  if (typeof options.callModel !== 'function') {
    return { ...deterministic, phrasedBy: 'deterministic', modelFallback: 'no model caller supplied' };
  }

  const prompt = [
    'You are a review assistant. Answer the question using ONLY the facts below.',
    'Do not add findings, exploitability claims, approvals, or symbols not in the facts.',
    'Keep the answer to two sentences.',
    '',
    ...(Array.isArray(options.history) && options.history.length
      ? ['Previous turns:', ...options.history.slice(-4).map((turn) => `Q: ${turn.q || turn.question || ''}\nA: ${turn.a || turn.answer || ''}`), '']
      : []),
    `Question: ${question}`,
    `Facts: ${JSON.stringify(deterministic.citations)}`,
    `Deterministic answer: ${deterministic.answer}`,
    `Posture: ${deterministic.posture}`
  ].join('\n');

  try {
    const text = await options.callModel(prompt);
    const answer = String(text || '').trim();
    const ungrounded = hasUngroundedBacktickSymbol(answer, allowedChatSymbols(receipt, deterministic));
    if (!answer || ungrounded) {
      return {
        ...deterministic,
        phrasedBy: 'deterministic',
        modelFallback: ungrounded ? `model cited ungrounded symbol ${ungrounded}` : 'model returned no answer'
      };
    }
    return { ...deterministic, answer, phrasedBy: 'model' };
  } catch (err) {
    return { ...deterministic, phrasedBy: 'deterministic', modelFallback: err?.message || String(err) };
  }
}

export function createReviewModelCaller(options = {}) {
  const env = globalThis.process?.env || {};
  const endpoint = options.endpoint || env.RULE_DRAFT_ENDPOINT || 'http://127.0.0.1:3005/v1/chat/completions';
  const model = options.model || env.RULE_DRAFT_MODEL || 'opensoyce-sentry-7b-fused';
  return async (prompt) => {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        temperature: 0,
        messages: [
          { role: 'system', content: 'Answer only from the supplied facts. Do not invent findings.' },
          { role: 'user', content: prompt }
        ]
      })
    });
    if (!response.ok) throw new Error(`model endpoint returned ${response.status}`);
    const data = await response.json();
    return data?.choices?.[0]?.message?.content || '';
  };
}

export function buildIncrementalPlan(previousReceipt, nextReceipt) {
  const previous = bundleIdsOf(previousReceipt);
  const next = bundleIdsOf(nextReceipt);
  if (previous.length === 0 || next.length === 0) {
    return {
      needsFullReview: true,
      reason: 'A receipt is missing per-bundle IDs; incremental reuse is not established.',
      reusableBundles: [],
      reviewBundles: next,
      droppedBundles: [],
      reuseRatio: 0
    };
  }

  const previousSet = new Set(previous);
  const nextSet = new Set(next);
  const reusableBundles = previous.filter((bundle) => nextSet.has(bundle));
  const reviewBundles = next.filter((bundle) => !previousSet.has(bundle));
  const droppedBundles = previous.filter((bundle) => !nextSet.has(bundle));

  return {
    needsFullReview: false,
    reason: reviewBundles.length === 0
      ? 'All next bundles are content-addressed matches from the previous receipt.'
      : 'Only changed or new bundles need re-evaluation; unchanged bundles are reusable.',
    previousHeadSha: isResolvedSha(previousReceipt.git?.headSha) ? previousReceipt.git.headSha : null,
    nextHeadSha: isResolvedSha(nextReceipt.git?.headSha) ? nextReceipt.git.headSha : null,
    reusableBundles,
    reviewBundles,
    droppedBundles,
    reuseRatio: next.length ? Number((reusableBundles.length / next.length).toFixed(4)) : 0
  };
}

export function buildZeroConfigInstall(options = {}) {
  return {
    packageName: 'roninos',
    apiKeyRequired: false,
    commands: {
      review: 'npx roninos audit "origin/main...HEAD" --sarif',
      mcp: 'npx roninos mcp'
    },
    githubAction: {
      uses: 'freewho99/roninos-review-action@v1.0.7',
      note: 'Pin the reviewed release tag. PR summary, line comments, receipt chat, and verified suggestions are delivered by the public action.'
    },
    notes: [
      'No API key is required for the deterministic gate or the local MCP server.',
      'An LLM is optional and only explains gate findings; it does not decide the verdict.',
      'Use a pinned GitHub Action ref in production rather than a floating branch.'
    ],
    ...options
  };
}

export { NON_CLAIMS as REVIEW_EXPERIENCE_NON_CLAIMS };
