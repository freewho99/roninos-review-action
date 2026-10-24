import { answerReviewQuestion } from './reviewExperience.js';

const RECEIPT_PATTERN = /<!-- roninos-receipt:([A-Za-z0-9_-]+) -->/;
const CHAT_MARKER = (sourceCommentId) => `<!-- roninos-chat:${String(sourceCommentId).replace(/[^0-9]/g, '')} -->`;

function compactText(value, max = 600) {
  const text = String(value || '');
  return text.length > max ? `${text.slice(0, max)}...` : text;
}

export function compactReceipt(receipt) {
  const checks = (receipt?.checks || []).slice(0, 40).map((check) => ({
    id: check.id,
    ruleId: check.ruleId,
    status: check.status,
    file: check.file,
    line: check.line,
    category: check.category,
    cwe: check.cwe,
    severity: check.severity,
    details: compactText(check.details || check.message, 300),
    patchStatus: check.patchStatus,
    patchVerified: check.patchVerified === true,
  }));
  const bundles = (receipt?.bundleReceipts || []).slice(0, 40).map((bundle) => ({
    bundleId: bundle.bundleId,
    status: bundle.status,
  }));
  return {
    receiptId: receipt?.receiptId || receipt?.receipt_id || null,
    status: receipt?.status || null,
    posture: receipt?.posture || null,
    elapsedMs: receipt?.elapsedMs || null,
    attestation: receipt?.attestation || null,
    publicKeyPem: receipt?.publicKeyPem || null,
    git: {
      headSha: receipt?.git?.headSha || null,
      baseSha: receipt?.git?.baseSha || null,
      repository: receipt?.git?.repository || null,
    },
    checks,
    bundleReceipts: bundles,
  };
}

export function encodeReceiptMarker(receipt) {
  const json = JSON.stringify(compactReceipt(receipt));
  return `<!-- roninos-receipt:${Buffer.from(json, 'utf8').toString('base64url')} -->`;
}

export function decodeReceiptMarker(body) {
  const match = RECEIPT_PATTERN.exec(String(body || ''));
  if (!match) return null;
  try {
    return JSON.parse(Buffer.from(match[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

export function selectReceiptComment(comments = []) {
  let selected = null;
  for (const comment of comments) {
    const receipt = decodeReceiptMarker(comment?.body);
    if (receipt) selected = { receipt, comment };
  }
  return selected;
}

export function stripMention(question) {
  return String(question || '').replace(/@(roninos|opensoyce)\b/gi, '').trim();
}

export function buildChatReply({ question, receipt, user, sourceCommentId }) {
  const answer = answerReviewQuestion(question, receipt);
  const login = String(user || '').replace(/[^a-zA-Z0-9-]/g, '');
  const body = [
    CHAT_MARKER(sourceCommentId),
    login ? `@${login}` : '',
    '',
    answer.answer,
    '',
    `> Receipt \`${receipt?.receiptId || 'unavailable'}\` · grounded in the PR receipt; not an approval or safety verdict.`,
  ].filter((line, index) => line || index > 0).join('\n');
  return { body, answer, marker: CHAT_MARKER(sourceCommentId) };
}
