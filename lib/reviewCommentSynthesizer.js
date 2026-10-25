// src/shared/architecturalAperture/reviewCommentSynthesizer.js
// ────────────────────────────────────────────────────────────────────────────
// RoninOS GitHub PR Review Comment Synthesizer
// Produces doctrine-compliant ("Records, not verdicts") GitHub PR feedback:
// 1. Top-Level PR Review Summary (PR-comment sized Markdown)
// 2. Line-Anchored Inline Diff Comments (GitHub REST/GraphQL Review API payload)
// ────────────────────────────────────────────────────────────────────────────

import { buildPrSummary } from './reviewExperience.js';

/**
 * Format policy posture badge.
 * Values: DENY (modeled violation; merge enforcement is separate), WARN (observations),
 * ALLOW (no modeled violation observed).
 */
export function getPolicyPosture(failedChecks = []) {
  if (failedChecks.length === 0) return 'ALLOW';
  const hasCritical = failedChecks.some(c => 
    c.severity === 'critical' || 
    c.id?.startsWith('INV_PG_') || 
    c.id?.startsWith('INV_CLOUD_') || 
    c.id?.startsWith('INV_WEB3_') || 
    c.id?.startsWith('SEC-CMD-') || 
    c.id?.startsWith('SEC-SQL-')
  );
  return hasCritical ? 'DENY' : 'WARN';
}

/**
 * Synthesizes a structured audit receipt from LiveCodeGuardRunner or PolyglotApertureEngine
 * into GitHub-ready PR comments.
 *
 * @param {Object} auditResult - Output from LiveCodeGuardRunner.runAudit or runPolyglotAudit
 * @param {Object} options
 * @param {string} [options.prNumber]
 * @param {string} [options.repoName]
 * @param {string} [options.canvasBaseUrl]
 * @returns {{ summaryMarkdown: string, inlineComments: Array<{ path: string, line: number, side: string, body: string }>, posture: string }}
 */
export function synthesizeReviewComments(auditResult, options = {}) {
  const checks = auditResult.checks || [];
  const failedChecks = checks.filter(c => c.status === 'FAILED' || c.status === 'VIOLATION');
  const passedChecks = checks.filter(c => c.status === 'PASSED' || c.status === 'VERIFIED');
  const elapsedMs = auditResult.elapsedMs || 1.25;
  const receiptId = auditResult.receiptId || auditResult.receipt_id || null;
  const prSummary = buildPrSummary(auditResult, { title: options.title || 'RoninOS Review' });
  const posture = prSummary.posture === 'MODELED_VIOLATION'
    ? 'DENY'
    : prSummary.posture === 'OBSERVATIONS_ONLY'
      ? 'WARN'
      : (prSummary.posture === 'ANALYSIS_INCOMPLETE' || prSummary.posture === 'ANALYZER_EXECUTION_INCOMPLETE')
        ? 'INCOMPLETE'
        : prSummary.posture === 'STRICT_COVERAGE_GAP'
          ? 'DENY'
          : prSummary.posture === 'PASS_WITH_UNASSESSED_SCOPE'
            ? 'ALLOW'
            : prSummary.posture === 'UNASSESSED_COVERAGE'
              ? 'UNASSESSED'
              : prSummary.posture === 'NO_APPLICABLE_CHECKS'
                ? 'NO_RULES'
                : prSummary.posture === 'UNRESOLVED_CROSS_BOUNDARY'
                  ? 'UNRESOLVED'
                  : 'ALLOW';

  const gateVerdict = auditResult.gateVerdict || (posture === 'DENY' || posture === 'INCOMPLETE' ? 'DENY' : 'ALLOW');

  // ──────────────────────────────────────────────────────────────────────────
  // 1. TOP-LEVEL PR REVIEW SUMMARY (Markdown)
  // ──────────────────────────────────────────────────────────────────────────
  const summaryMarkdown = prSummary.markdown;

  // ──────────────────────────────────────────────────────────────────────────
  // 2. LINE-ANCHORED INLINE DIFF COMMENTS (GitHub Review API Payload)
  // ──────────────────────────────────────────────────────────────────────────
  const inlineComments = [];

  for (const check of failedChecks) {
    const file = check.file || auditResult.git?.stagedFiles?.[0] || 'src/code.ts';
    const line = check.line || 1;
    const cwe = check.cwe || (check.details?.match(/CWE-\d+/) ? check.details.match(/CWE-\d+/)[0] : 'AST-INVARIANT');

    let body = `<!-- roninos-rule:${String(check.id || 'UNKNOWN').replace(/[^a-zA-Z0-9_.-]/g, '')} -->\n`;
    body += `#### RoninOS: modeled invariant finding (\`${check.id}\`)\n\n`;
    body += `**Category:** ${check.category || 'Architectural / State Invariant'} (${cwe})  \n`;
    body += `**Observation:** ${check.details || 'Modeled invariant boundary condition observed.'}\n\n`;

    if (check.suggestionVerified === true && check.suggestion) {
      body += `**Verified patch (Tree-sitter clean parse & semantic smoke test):**\n`;
      body += `\`\`\`suggestion\n${check.suggestion}\n\`\`\`\n\n`;
      body += `*Patch proof:* \`${check.patchStatus || 'PROVEN_SEMANTICALLY_SOUND'}\`\n\n`;
    } else if (check.patch) {
      body += `**Patch candidate (not applied):**\n`;
      body += `\`\`\`diff\n${check.patch.trim()}\n\`\`\`\n\n`;
      const patchStatus = check.patchStatus === 'VERIFIED_CLEAN_AST'
        ? 'PATCH_CANDIDATE_UNVERIFIED'
        : (check.patchStatus || 'PATCH_CANDIDATE_UNVERIFIED');
      body += `*Patch status:* \`${patchStatus}\`\n\n`;
    } else {
      body += `**Remediation guidance:**\n`;
      body += `Review the modeled boundary condition and the surrounding invariant before changing code.\n\n`;
    }

    body += receiptId
      ? `> *Receipt \`${receiptId}\` · audit observation; not a safety verdict.*`
      : '> *No receipt ID was recorded in this audit result.*';
    body += auditResult.attestation?.signature
      ? `\n> *Audit Engine Ed25519: \`${auditResult.attestation.signature}\` · key \`${auditResult.attestation.keyFingerprint || 'unknown'}\`*`
      : '\n> *Unsigned observation: no Ed25519 attestation was recorded.*';

    const startLine = Number(check.suggestionStartLine);
    const endLine = Number(check.suggestionEndLine || line);
    inlineComments.push({
      path: file,
      line: endLine,
      ...(Number.isInteger(startLine) && startLine > 0 && endLine > startLine ? { start_line: startLine } : {}),
      side: 'RIGHT',
      body
    });
  }

  return {
    summaryMarkdown,
    inlineComments,
    posture,
    gateVerdict,
    receiptId,
    elapsedMs,
    totalChecks: checks.length,
    failedCount: failedChecks.length,
    passedCount: passedChecks.length,
    coverage: prSummary.coverage
  };
}
