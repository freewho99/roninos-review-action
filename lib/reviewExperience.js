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

const SUPPORTED_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.go', '.rs', '.java', '.c', '.cpp', '.cc', '.h', '.hpp',
  '.sol', '.rb'
]);

function formatForExt(ext) {
  const map = {
    '.tf': 'terraform',
    '.hcl': 'hcl',
    '.yaml': 'yaml',
    '.yml': 'yaml',
    '.proto': 'protobuf',
    '.kt': 'kotlin',
    '.swift': 'swift',
    '.sql': 'sql',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.py': 'python',
    '.go': 'go',
    '.rs': 'rust',
    '.java': 'java',
    '.c': 'c',
    '.cpp': 'cpp',
    '.sol': 'solidity'
  };
  return map[ext] || (ext.startsWith('.') ? ext.slice(1) : ext) || 'unknown';
}

function isSupportedFormat(ext) {
  return SUPPORTED_EXTENSIONS.has(ext);
}

function summarizeCoverage(files = []) {
  return {
    total: files.length,
    completed: files.filter((f) => f.status === 'COMPLETED').length,
    noApplicableRules: files.filter((f) => f.status === 'NO_APPLICABLE_RULES').length,
    incomplete: files.filter((f) => f.status === 'ANALYSIS_INCOMPLETE').length,
    unassessed: files.filter((f) => f.status === 'UNASSESSED_FORMAT').length
  };
}

export function normalizeCoverage(receipt) {
  if (receipt.coverage && Array.isArray(receipt.coverage.files)) {
    return {
      files: receipt.coverage.files,
      summary: receipt.coverage.summary || summarizeCoverage(receipt.coverage.files)
    };
  }
  if (Array.isArray(receipt.coverage)) {
    return {
      files: receipt.coverage,
      summary: summarizeCoverage(receipt.coverage)
    };
  }

  // Derive coverage from files and checks if not explicitly supplied
  const files = filesOf(receipt);
  const checks = receipt.checks || [];

  const derivedFiles = files.map((filePath) => {
    const ext = (filePath.match(/\.[0-9a-z]+$/i) || [''])[0].toLowerCase();
    const format = formatForExt(ext);
    const formatSupported = isSupportedFormat(ext);

    const fileChecks = checks.filter((c) => c.file === filePath);
    const checksAttempted = fileChecks.length;
    const checksCompleted = fileChecks.filter((c) => c.status !== 'SKIPPED' && c.status !== 'UNRESOLVED').length;

    let status = 'COMPLETED';
    let reason = null;

    if (!formatSupported) {
      status = 'UNASSESSED_FORMAT';
      reason = `No active analyzer configured for ${format || ext || 'this format'}.`;
    } else if (fileChecks.some((c) => c.status === 'ERROR' || c.status === 'ANALYSIS_INCOMPLETE' || c.error)) {
      status = 'ANALYSIS_INCOMPLETE';
      const errCheck = fileChecks.find((c) => c.status === 'ERROR' || c.status === 'ANALYSIS_INCOMPLETE' || c.error);
      reason = errCheck?.details || errCheck?.error || 'Analysis incomplete: parser or execution failure';
    } else if (fileChecks.length === 0 || fileChecks.every((c) => c.status === 'SKIPPED')) {
      status = 'NO_APPLICABLE_RULES';
      reason = 'No applicable modeled rules matched this change.';
    }

    return {
      path: filePath,
      format,
      formatSupported,
      checksAttempted,
      checksCompleted,
      status,
      reason
    };
  });

  return {
    files: derivedFiles,
    summary: summarizeCoverage(derivedFiles)
  };
}

export const NON_EXECUTABLE_EXTENSIONS = new Set([
  '.md', '.txt', '.rst', '.gitignore', '.editorconfig', '.png', '.jpg', '.svg', '.ico', '.lock'
]);

/**
 * Evaluates file coverage states and decouples epistemic reporting from merge blocking.
 */
export function synthesizeReviewDecision({
  changedFiles = [],
  fileAssessments = new Map(), // filePath -> { state: 'COMPLETED' | 'ANALYSIS_INCOMPLETE' | 'UNASSESSED_FORMAT', findings: [] }
  policy = {
    failOnIncompleteAnalysis: true,
    strictCoverageGlobs: [] // e.g., [/^infra\//, /^proto\//]
  }
}) {
  const policyOpts = {
    failOnIncompleteAnalysis: policy?.failOnIncompleteAnalysis ?? true,
    strictCoverageGlobs: policy?.strictCoverageGlobs ?? []
  };

  const coverageBuckets = {
    COMPLETED: [],
    NO_APPLICABLE_RULES: [],
    UNASSESSED_FORMAT: [],
    ANALYSIS_INCOMPLETE: []
  };

  const blockingFailures = [];
  const observations = [];
  const strictCoverageViolations = [];

  const getAssessment = (path) => {
    if (fileAssessments instanceof Map) return fileAssessments.get(path);
    if (fileAssessments && typeof fileAssessments === 'object') return fileAssessments[path];
    return undefined;
  };
  const hasAssessment = (path) => {
    if (fileAssessments instanceof Map) return fileAssessments.has(path);
    if (fileAssessments && typeof fileAssessments === 'object') return Object.prototype.hasOwnProperty.call(fileAssessments, path);
    return false;
  };

  for (const filePath of changedFiles) {
    const ext = filePath.slice(filePath.lastIndexOf('.')).toLowerCase();

    if (NON_EXECUTABLE_EXTENSIONS.has(ext) && !hasAssessment(filePath)) {
      coverageBuckets.NO_APPLICABLE_RULES.push(filePath);
      continue;
    }

    const assessment = getAssessment(filePath);
    if (!assessment) {
      coverageBuckets.UNASSESSED_FORMAT.push(filePath);
      const isStrict = policyOpts.strictCoverageGlobs.some((re) => re.test(filePath));
      if (isStrict) {
        strictCoverageViolations.push({
          file: filePath,
          reason: 'UNASSESSED_FORMAT_IN_STRICT_PATH'
        });
      }
      continue;
    }

    const state = assessment.state || assessment.status || 'COMPLETED';
    coverageBuckets[state]?.push(filePath);

    for (const f of assessment.findings || assessment.checks || []) {
      if (f.status === 'FAILED') blockingFailures.push(f);
      else if (f.status === 'OBSERVATION') observations.push(f);
    }
  }

  // Determine Gate Verdict independently from Coverage Disclosure
  let gateVerdict = 'ALLOW';
  let gatePosture = 'VERIFIED_CLEAN';

  if (blockingFailures.length > 0) {
    gateVerdict = 'DENY';
    gatePosture = 'MODELED_VIOLATION';
  } else if (coverageBuckets.ANALYSIS_INCOMPLETE.length > 0 && policyOpts.failOnIncompleteAnalysis) {
    gateVerdict = 'DENY';
    gatePosture = 'ANALYZER_EXECUTION_INCOMPLETE';
  } else if (strictCoverageViolations.length > 0) {
    gateVerdict = 'DENY';
    gatePosture = 'STRICT_COVERAGE_GAP';
  } else if (coverageBuckets.UNASSESSED_FORMAT.length > 0) {
    // Do NOT block merge by default on unmodeled files, but disclose honestly in receipt
    gateVerdict = 'ALLOW';
    gatePosture = 'PASS_WITH_UNASSESSED_SCOPE';
  }

  return {
    gateVerdict,      // 'ALLOW' | 'DENY'
    gatePosture,      // Explicit posture without conflating scope notes with failures
    coverageBuckets,  // Always rendered in PR summary & cryptographic receipt
    blockingFailures,
    observations,
    strictCoverageViolations
  };
}

export function postureOf(receipt) {
  if (receipt.gatePosture) return receipt.gatePosture;
  if (receipt.policy && (receipt.fileAssessments || receipt.changedFiles)) {
    const decision = synthesizeReviewDecision({
      changedFiles: receipt.changedFiles || filesOf(receipt),
      fileAssessments: receipt.fileAssessments || new Map(),
      policy: receipt.policy
    });
    return decision.gatePosture;
  }
  const failed = (receipt.checks || []).filter((check) => check.status === 'FAILED');
  const unresolved = (receipt.checks || []).filter((check) => check.status === 'UNRESOLVED');
  const observed = (receipt.checks || []).filter((check) => check.status === 'OBSERVATION');
  if (failed.length > 0) return 'MODELED_VIOLATION';
  if (unresolved.length > 0) return 'UNRESOLVED_CROSS_BOUNDARY';
  if (observed.length > 0) return 'OBSERVATIONS_ONLY';

  const coverage = normalizeCoverage(receipt);
  const files = coverage.files || [];

  if (files.length > 0) {
    const incomplete = files.filter((f) => f.status === 'ANALYSIS_INCOMPLETE');
    if (incomplete.length > 0) return 'ANALYSIS_INCOMPLETE';

    const unassessed = files.filter((f) => f.status === 'UNASSESSED_FORMAT');
    if (unassessed.length === files.length) return 'UNASSESSED_COVERAGE';

    const noRules = files.filter((f) => f.status === 'NO_APPLICABLE_RULES');
    if (noRules.length === files.length) return 'NO_APPLICABLE_CHECKS';

    if (unassessed.length > 0 && files.every((f) => f.status === 'UNASSESSED_FORMAT' || f.status === 'NO_APPLICABLE_RULES')) {
      return 'UNASSESSED_COVERAGE';
    }
  }

  return 'NO_MODELED_VIOLATION';
}

function findingsOf(receipt) {
  return (receipt.checks || [])
    .filter((check) => check.status === 'FAILED' || check.status === 'OBSERVATION' || check.status === 'UNRESOLVED')
    .map((check) => ({
      ruleId: check.id || check.ruleId || 'UNKNOWN_RULE',
      status: check.status,
      tier: check.tier || null,
      file: check.file || null,
      line: check.line || null,
      cwe: check.cwe || null,
      bundleId: check.bundleId || null,
      details: check.details || check.message || '',
      patchVerified: check.patchVerified === true
        || check.suggestionVerified === true
        || check.patchStatus === 'PROVEN_COMPLIANT_BY_AST_AND_GATE'
        || check.patchStatus === 'PROVEN_SEMANTICALLY_SOUND'
        || check.patchStatus === 'PROVEN_STATIC_SEMANTIC'
        || check.patchStatus === 'PROVEN_CLEAN_TREE_SITTER'
        || check.patchProof?.verified === true
    }));
}

function bundleIdsOf(receipt) {
  return [...new Set((receipt.bundleReceipts || []).map((bundle) => bundle.bundleId).filter(Boolean))].sort();
}

function filesOf(receipt) {
  const diffFiles = receipt.git?.stagedFiles || receipt.git?.changedFiles || receipt.changedFiles;
  if (Array.isArray(diffFiles) && diffFiles.length > 0) {
    return [...new Set(diffFiles)].sort();
  }
  const checks = receipt.checks || [];
  const bundles = receipt.bundleReceipts || [];
  const covFiles = (receipt.coverage?.files || (Array.isArray(receipt.coverage) ? receipt.coverage : [])).map((f) => f.path);
  return [...new Set([
    ...checks.map((check) => check.file).filter(Boolean),
    ...bundles.flatMap((bundle) => bundle.files || bundle.filePaths || []),
    ...covFiles.filter(Boolean)
  ])].sort();
}

function proofCount(receipt) {
  return (receipt.checks || []).filter((check) =>
    check.patchVerified === true
    || check.suggestionVerified === true
    || check.patchStatus === 'PROVEN_COMPLIANT_BY_AST_AND_GATE'
    || check.patchStatus === 'PROVEN_SEMANTICALLY_SOUND'
    || check.patchStatus === 'PROVEN_STATIC_SEMANTIC'
    || check.patchStatus === 'PROVEN_CLEAN_TREE_SITTER'
    || check.proverGrade === 'PROVEN_COMPLIANT_BY_AST_AND_GATE'
    || check.patchProof?.verified === true
  ).length;
}

export function buildPrSummary(receipt, options = {}) {
  const posture = postureOf(receipt);
  const findings = findingsOf(receipt);
  const failed = findings.filter((finding) => finding.status === 'FAILED');
  const unresolved = findings.filter((finding) => finding.status === 'UNRESOLVED');
  const observed = findings.filter((finding) => finding.status === 'OBSERVATION');
  const bundles = bundleIdsOf(receipt);
  const files = filesOf(receipt);
  const headSha = isResolvedSha(receipt.git?.headSha) ? receipt.git.headSha : null;
  const proof = proofCount(receipt);
  const title = options.title || 'RoninOS Review';

  const coverage = normalizeCoverage(receipt);
  const covSummary = coverage.summary;
  const unassessedFiles = coverage.files.filter((f) => f.status === 'UNASSESSED_FORMAT');
  const incompleteFiles = coverage.files.filter((f) => f.status === 'ANALYSIS_INCOMPLETE');

  const findingsSummary = unresolved.length > 0
    ? `${failed.length} blocked, ${unresolved.length} unresolved, ${observed.length} observed`
    : `${failed.length} blocked, ${observed.length} observed`;

  const lines = [
    `## ${title}`,
    '',
    `**Gate posture:** \`${posture}\`  `,
    `**Head SHA:** ${headSha ? `\`${headSha}\`` : '`unavailable` (no resolved commit identity)'}  `,
    `**Bundles:** ${bundles.length} · **Changed files:** ${files.length} · **Findings:** ${findingsSummary} · **Verified patches:** ${proof}`,
    ''
  ];

  // 1. Blocked findings
  if (failed.length > 0) {
    lines.push('### Blocked modeled findings', '', '| Rule | File | Line | CWE | Observation |', '|---|---|---:|---|---|');
    for (const finding of failed) {
      lines.push(`| \`${finding.ruleId}\` | \`${finding.file || 'unknown'}\` | ${finding.line || '—'} | ${finding.cwe || '—'} | ${String(finding.details).replace(/\|/g, '\\|')} |`);
    }
    lines.push('');
  }

  // 1b. Unresolved cross-boundary checks (missing evidence)
  if (unresolved.length > 0) {
    lines.push('### Unresolved cross-boundary evidence', '', '| Rule | File | Details |', '|---|---|---|');
    for (const finding of unresolved) {
      lines.push(`| \`${finding.ruleId}\` | \`${finding.file || 'unknown'}\` | ${String(finding.details).replace(/\|/g, '\\|')} |`);
    }
    lines.push('');
  }

  // 2. Observations
  if (observed.length > 0) {
    lines.push('### Observations (non-blocking)', '', '| Rule | File | Details |', '|---|---|---|');
    for (const finding of observed) {
      lines.push(`| \`${finding.ruleId}\` | \`${finding.file || 'unknown'}\` | ${String(finding.details).replace(/\|/g, '\\|')} |`);
    }
    lines.push('');
  }

  // 3. Unassessed formats (Case 1 & Case 4)
  if (unassessedFiles.length > 0) {
    lines.push(
      failed.length > 0 || observed.length > 0
        ? '### Coverage Gaps & Limitations'
        : '### Unassessed Coverage',
      ''
    );
    lines.push('The following file(s) are in unmodeled formats and were not evaluated by an active analyzer:');
    for (const file of unassessedFiles) {
      lines.push(`- \`${file.path}\` (${file.format || 'unsupported'}): ${file.reason || 'No active analyzer configured.'}`);
    }
    lines.push('');
    if (failed.length === 0 && observed.length === 0) {
      lines.push('Infrastructure or unmodeled coverage was not evaluated for this change. This is not a clean pass or approval.', '');
    }
  }

  // 4. Incomplete analysis / parser failures (Case 2)
  if (incompleteFiles.length > 0) {
    lines.push('### Analysis Incomplete', '');
    lines.push('Analysis could not be completed for the following file(s):');
    for (const file of incompleteFiles) {
      lines.push(`- \`${file.path}\`: ${file.reason || 'Parser or execution failure.'}`);
    }
    lines.push('');
  }

  // 5. No applicable rules (Case 3)
  if (posture === 'NO_APPLICABLE_CHECKS') {
    lines.push('### Scope Statement', '');
    lines.push('No applicable modeled checks matched this change. The diff does not touch any modeled invariant boundaries. This is not approval and does not imply that unmodeled defects are absent.', '');
  }

  // 6. Clean pass on fully evaluated files with 0 findings
  if (posture === 'NO_MODELED_VIOLATION' && findings.length === 0 && unassessedFiles.length === 0 && incompleteFiles.length === 0) {
    lines.push('No modeled invariant failed on this change. This is not approval and does not cover unmodeled defects.', '');
  }

  // 7. Verified remediation patches
  if (proof > 0) {
    lines.push(`### Proof`, '', `${proof} remediation patch(es) passed the closed-loop post-image gate.`, '');
  }

  // 8. Changed files breakdown
  if (files.length > 0) {
    lines.push('### Changed files', '', ...files.map((file) => `- \`${file}\``), '');
  }

  // 9. REA bundles
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
      verifiedPatches: proof,
      coverage: covSummary
    },
    findings,
    coverage,
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
    const coverage = normalizeCoverage(receipt);
    const incomplete = coverage.files.filter((f) => f.status === 'ANALYSIS_INCOMPLETE');
    if (incomplete.length > 0 && failed.length === 0) {
      return answer(
        `Analysis is incomplete: ${incomplete.length} file(s) failed (${incomplete.map((f) => `${f.path}: ${f.reason}`).join('; ')}).`,
        incomplete.map((f) => ({ file: f.path, status: f.status, reason: f.reason }))
      );
    }
    if (failed.length === 0) return answer('No modeled invariant failed in this receipt. That is not approval and does not cover unmodeled defects.', citations);
    return answer(
      `${failed.length} modeled finding(s) are in DENY posture: ${failed.map((finding) => `${finding.ruleId} at ${finding.file || 'unknown'}${finding.line ? `:${finding.line}` : ''}${finding.details ? ` (${finding.details})` : ''}`).join('; ')}.`,
      failed.map((finding) => ({ ruleId: finding.ruleId, file: finding.file, line: finding.line, bundleId: finding.bundleId, details: finding.details }))
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

  if (/\b(coverage|unassessed|unsupported|incomplete|terraform|iac|scope|cross-boundary|protobuf|proto|contract|unresolved)\b/i.test(text)) {
    const coverage = normalizeCoverage(receipt);
    const unresolvedChecks = (receipt.checks || []).filter((c) => c.status === 'UNRESOLVED');
    if (unresolvedChecks.length > 0) {
      return answer(
        `Cross-boundary contract verification is unresolved: ${unresolvedChecks.map((c) => `${c.file || 'contract'}: ${c.details}`).join('; ')}`,
        unresolvedChecks.map((c) => ({ file: c.file, status: c.status, rule: c.id || c.ruleId, details: c.details }))
      );
    }
    const unassessed = coverage.files.filter((f) => f.status === 'UNASSESSED_FORMAT');
    const incomplete = coverage.files.filter((f) => f.status === 'ANALYSIS_INCOMPLETE');
    const noRules = coverage.files.filter((f) => f.status === 'NO_APPLICABLE_RULES');
    const completed = coverage.files.filter((f) => f.status === 'COMPLETED');

    if (unassessed.length > 0) {
      return answer(
        `Coverage is partial: ${unassessed.length} file(s) are in unassessed formats (${unassessed.map((f) => `${f.path}: ${f.reason}`).join('; ')}).`,
        unassessed.map((f) => ({ file: f.path, status: f.status, reason: f.reason }))
      );
    }
    if (incomplete.length > 0) {
      return answer(
        `Analysis is incomplete: ${incomplete.length} file(s) failed (${incomplete.map((f) => `${f.path}: ${f.reason}`).join('; ')}).`,
        incomplete.map((f) => ({ file: f.path, status: f.status, reason: f.reason }))
      );
    }
    if (noRules.length === coverage.files.length && coverage.files.length > 0) {
      return answer(
        `No applicable modeled checks matched the changed code. Diff did not touch modeled invariant boundaries.`,
        [{ files: coverage.files.map((f) => f.path), status: 'NO_APPLICABLE_RULES' }]
      );
    }
    return answer(
      `Coverage evaluated across ${completed.length} file(s) (${completed.map((f) => f.path).join(', ')}) and ${bundles.length} bundle(s).`,
      [{ evaluated: completed.length, files: completed.map((f) => f.path), bundles: bundles.length }]
    );
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
