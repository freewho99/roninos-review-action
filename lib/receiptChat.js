import crypto from 'node:crypto';
import { answerReviewQuestion } from './reviewExperience.js';

const RECEIPT_PATTERN = /<!-- roninos-receipt:([A-Za-z0-9_-]+) -->/;
const CHAT_MARKER = (sourceCommentId) => `<!-- roninos-chat:${String(sourceCommentId).replace(/[^0-9]/g, '')} -->`;

function compactText(value, max = 600) {
  const text = String(value || '');
  return text.length > max ? `${text.slice(0, max)}...` : text;
}

export function compactReceipt(receipt) {
  const allChecks = receipt?.checks || [];
  const checks = [...allChecks]
    .sort((a, b) => Number(b.status === 'FAILED' || b.status === 'VIOLATION') - Number(a.status === 'FAILED' || a.status === 'VIOLATION'))
    .slice(0, 40)
    .map((check) => ({
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
  const original = receipt?.signedReceiptOriginal || receipt;
  const rawReceipt = original ? JSON.stringify(original) : '';
  return {
    signedReceipt: rawReceipt.length <= 30000 ? original : null,
    receiptId: receipt?.receiptId || receipt?.receipt_id || null,
    status: receipt?.status || null,
    posture: receipt?.posture || null,
    elapsedMs: receipt?.elapsedMs || null,
    attestation: receipt?.attestation || null,
    commentAttestation: receipt?.commentAttestation || null,
    publicKeyPem: receipt?.publicKeyPem || null,
    git: {
      headSha: receipt?.git?.headSha || null,
      baseSha: receipt?.git?.baseSha || null,
      repository: receipt?.git?.repository || null,
    },
    checks,
    truncatedChecks: allChecks.length > 40,
    totalChecks: allChecks.length,
    bundleReceipts: bundles,
  };
}

function sorted(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(sorted);
  const out = {};
  for (const key of Object.keys(value).sort()) {
    if (value[key] !== undefined) out[key] = sorted(value[key]);
  }
  return out;
}

export function canonicalCompactReceipt(receipt) {
  const copy = { ...receipt };
  delete copy.commentAttestation;
  delete copy.signedReceiptOriginal;
  return JSON.stringify(sorted(copy));
}

export function signCompactReceipt(receipt, privateKeyPem, publicKeyPem) {
  const signature = crypto.sign(
    null,
    Buffer.from(canonicalCompactReceipt(receipt), 'utf8'),
    privateKeyPem,
  ).toString('base64');
  return {
    algorithm: 'Ed25519',
    keyFingerprint: `ed25519:${crypto.createHash('sha256').update(publicKeyPem).digest('hex').slice(0, 16)}`,
    signedAt: new Date().toISOString(),
    signature: `sig_ed25519_${signature}`,
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

const TRUSTED_RECEIPT_AUTHORS = new Set(['github-actions[bot]', 'roninos-app[bot]']);

function verifyCommentEnvelope(envelope) {
  // Older trusted bot comments predate the compact comment signature. The
  // author allowlist remains the publishing-identity check; when a signature is
  // present, it must verify.
  if (!envelope?.commentAttestation) return true;
  if (!envelope.publicKeyPem) return false;
  const signature = String(envelope.commentAttestation.signature || '').replace(/^sig_ed25519_/, '');
  if (!signature) return false;
  try {
    return crypto.verify(
      null,
      Buffer.from(canonicalCompactReceipt(envelope), 'utf8'),
      crypto.createPublicKey(envelope.publicKeyPem),
      Buffer.from(signature, 'base64'),
    );
  } catch {
    return false;
  }
}

export function selectReceiptComment(comments = [], { allowedAuthors = TRUSTED_RECEIPT_AUTHORS } = {}) {
  let selected = null;
  for (const comment of comments) {
    const author = comment?.user?.login;
    if (!author || !allowedAuthors.has(author)) continue;
    const envelope = decodeReceiptMarker(comment?.body);
    if (!envelope || !verifyCommentEnvelope(envelope)) continue;
    const receipt = envelope.signedReceipt || envelope;
    selected = { receipt, envelope, comment };
  }
  return selected;
}

export function stripMention(question) {
  return String(question || '').replace(/@(roninos|opensoyce)\b/gi, '').trim();
}

export function buildChatReply({ question, receipt, user, sourceCommentId }) {
  const answer = receipt?.truncatedChecks
    ? {
        grounded: false,
        answer: 'The embedded receipt was truncated before all checks could be retained. I cannot answer a conclusion question from an incomplete receipt; inspect the PR receipt artifact or ask about a specific finding.',
        citations: [],
      }
    : answerReviewQuestion(question, receipt);
  const login = String(user || '').replace(/[^a-zA-Z0-9-]/g, '');
  const body = [
    CHAT_MARKER(sourceCommentId),
    login ? `@${login}` : '',
    '',
    answer.answer,
    '',
    `> Receipt \`${receipt?.receiptId || 'unavailable'}\` - grounded in the PR receipt; not an approval or safety verdict.`,
  ].filter((line, index) => line || index > 0).join('\n');
  return { body, answer, marker: CHAT_MARKER(sourceCommentId) };
}
