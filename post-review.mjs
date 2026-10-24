#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

const MARKER = '<!-- roninos-review -->';
const DEFAULT_CHECK_NAME = 'RoninOS';

import { synthesizeReviewComments } from './lib/reviewCommentSynthesizer.js';
import { encodeReceiptMarker } from './lib/receiptChat.js';
import { verifySuggestion } from './lib/suggestionVerifier.js';

let parseTree;
let languageKeyForFile;
try {
  ({ parseTree, languageKeyForFile } = await import('roninos/lib/engineCore/ast.js'));
} catch {
  ({ parseTree, languageKeyForFile } = await import('../../src/shared/architecturalAperture/engineCore/ast.js'));
}

function readJson(file) {
  const receiptRoot = path.resolve(process.env.RONINOS_RECEIPT_ROOT || process.env.RUNNER_TEMP || process.cwd());
  const resolved = path.resolve(receiptRoot, file);
  if (resolved !== receiptRoot && !resolved.startsWith(receiptRoot + path.sep)) {
    throw new Error('RECEIPT_PATH_OUTSIDE_ALLOWED_ROOT');
  }
  return JSON.parse(fs.readFileSync(resolved, 'utf8').replace(/^\uFEFF/, ''));
}

function conclusionFor(receipt) {
  const failed = (receipt.checks || []).filter((check) => check.status === 'FAILED' || check.status === 'VIOLATION');
  return failed.length > 0 || receipt.status === 'INVARIANT_VIOLATION' ? 'failure' : 'success';
}

async function fetchFileContent({ fetchImpl, token, repo, filePath, ref }) {
  if (!token || !repo || !ref || !filePath) return null;
  const encoded = String(filePath).split('/').map(encodeURIComponent).join('/');
  const res = await githubFetch(
    fetchImpl,
    token,
    `https://api.github.com/repos/${repo}/contents/${encoded}?ref=${encodeURIComponent(ref)}`,
  );
  if (!res.ok) return null;
  const data = await res.json();
  if (data?.encoding !== 'base64' || !data.content) return null;
  return Buffer.from(data.content, 'base64').toString('utf8');
}

export async function prepareReceipt({
  receipt,
  fetchImpl = fetch,
  token,
  repo,
  headSha,
  fileContents = {},
  publicKeyPem = null,
}) {
  const prepared = JSON.parse(JSON.stringify(receipt));
  prepared.signedReceiptOriginal = JSON.parse(JSON.stringify(receipt));
  if (!prepared.git) prepared.git = {};
  if (!prepared.git.headSha && headSha) prepared.git.headSha = headSha;
  if (publicKeyPem) prepared.publicKeyPem = publicKeyPem;
  for (const check of prepared.checks || []) {
    if (!check.patch || !check.file) continue;
    const content = fileContents[check.file]
      || await fetchFileContent({ fetchImpl, token, repo, filePath: check.file, ref: headSha });
    if (!content) {
      check.suggestionVerified = false;
      continue;
    }
    const proof = await verifySuggestion({
      filePath: check.file,
      content,
      patch: check.patch,
      parseTree,
      languageKeyForFile,
    });
    check.suggestionVerified = proof.verified === true;
    if (proof.verified) {
      check.suggestion = proof.suggestion;
      check.suggestionStartLine = proof.startLine;
      check.suggestionEndLine = proof.endLine;
      check.patchStatus = 'PROVEN_CLEAN_TREE_SITTER';
    }
  }
  return prepared;
}

function receiptFooter(receipt) {
  const attestation = receipt?.attestation;
  if (!attestation?.signature) {
    return '> Receipt is unsigned: no Ed25519 attestation was recorded.';
  }
  return `> Receipt \`${receipt.receiptId || 'unknown'}\` · Ed25519 \`${attestation.signature}\` · key \`${attestation.keyFingerprint || 'unknown'}\``;
}

export function buildReviewPayload(receipt, options = {}) {
  const synthesized = synthesizeReviewComments(receipt, {
    title: options.title || 'RoninOS Review',
  });
  const comments = synthesized.inlineComments
    .filter((comment) => Number.isInteger(comment.line) && comment.line > 0)
    .map((comment) => ({
      path: comment.path,
      line: comment.line,
      ...(comment.start_line ? { start_line: comment.start_line } : {}),
      side: comment.side || 'RIGHT',
      body: comment.body,
    }));
  return {
    commitId: receipt.git?.headSha || options.headSha || null,
    body: `${MARKER}\n${synthesized.summaryMarkdown}\n\n${receiptFooter(receipt)}\n\n${encodeReceiptMarker(receipt)}`,
    comments,
    synthesized,
    conclusion: conclusionFor(receipt),
  };
}

async function githubFetch(fetchImpl, token, url, init = {}) {
  const response = await fetchImpl(url, {
    ...init,
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
  });
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  return { ok: response.ok, status: response.status, data };
}

async function findComment(fetchImpl, token, repo, prNumber) {
  for (let page = 1; page <= 3; page += 1) {
    const result = await githubFetch(
      fetchImpl,
      token,
      `https://api.github.com/repos/${repo}/issues/${prNumber}/comments?per_page=100&page=${page}`,
    );
    if (!result.ok) return { error: `list comments ${result.status}` };
    const comments = Array.isArray(result.data) ? result.data : [];
    const existing = comments.find((comment) => String(comment.body || '').includes(MARKER));
    if (existing) return { existing, page };
    if (comments.length < 100) break;
  }
  return { existing: null };
}

export async function upsertSummaryComment({ fetchImpl = fetch, token, repo, prNumber, body }) {
  const found = await findComment(fetchImpl, token, repo, prNumber);
  if (found.error) return { posted: false, error: found.error };
  if (found.existing) {
    const result = await githubFetch(
      fetchImpl,
      token,
      `https://api.github.com/repos/${repo}/issues/comments/${found.existing.id}`,
      { method: 'PATCH', body: JSON.stringify({ body }) },
    );
    return { posted: result.ok, id: found.existing.id, updated: true, status: result.status };
  }
  const created = await githubFetch(
    fetchImpl,
    token,
    `https://api.github.com/repos/${repo}/issues/${prNumber}/comments`,
    { method: 'POST', body: JSON.stringify({ body }) },
  );
  return { posted: created.ok, id: created.data?.id || null, updated: false, status: created.status };
}

async function findReview(fetchImpl, token, repo, prNumber) {
  for (let page = 1; page <= 3; page += 1) {
    const result = await githubFetch(
      fetchImpl,
      token,
      `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews?per_page=100&page=${page}`,
    );
    if (!result.ok) return { error: `list reviews ${result.status}` };
    const reviews = Array.isArray(result.data) ? result.data : [];
    const existing = reviews.find((review) => String(review.body || '').includes(MARKER));
    if (existing) return { existing };
    if (reviews.length < 100) break;
  }
  return { existing: null };
}

export async function upsertCheckRun({
  fetchImpl = fetch,
  token,
  repo,
  headSha,
  checkName = DEFAULT_CHECK_NAME,
  conclusion,
  title,
  summary,
}) {
  if (!headSha) return { posted: false, error: 'missing head SHA' };
  const listed = await githubFetch(
    fetchImpl,
    token,
    `https://api.github.com/repos/${repo}/commits/${headSha}/check-runs?check_name=${encodeURIComponent(checkName)}&per_page=100`,
  );
  if (!listed.ok) return { posted: false, error: `list check runs ${listed.status}` };
  const existing = (listed.data?.check_runs || []).find((run) => run.name === checkName);
  const updateBody = {
    name: checkName,
    status: 'completed',
    conclusion,
    external_id: 'roninos-review',
    output: { title, summary },
  };
  const createBody = { ...updateBody, head_sha: headSha };
  const result = existing
    ? await githubFetch(fetchImpl, token, `https://api.github.com/repos/${repo}/check-runs/${existing.id}`, {
        method: 'PATCH',
        body: JSON.stringify(updateBody),
      })
    : await githubFetch(fetchImpl, token, `https://api.github.com/repos/${repo}/check-runs`, {
        method: 'POST',
        body: JSON.stringify(createBody),
      });
  return {
    posted: result.ok,
    updated: Boolean(existing),
    id: result.data?.id || existing?.id || null,
    status: result.status,
    error: result.ok ? null : `post check run ${result.status}`,
  };
}

async function githubGraphql({ fetchImpl, token, query, variables }) {
  const response = await fetchImpl('https://api.github.com/graphql', {
    method: 'POST',
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ query, variables }),
  });
  if (!response.ok) return null;
  const data = JSON.parse(await response.text());
  if (Array.isArray(data.errors) && data.errors.length > 0) return null;
  return data.data;
}

export async function resolveSatisfiedThreads({
  fetchImpl = fetch,
  token,
  repo,
  prNumber,
  receipt,
  headSha,
}) {
  const failed = (receipt.checks || []).filter((check) => check.status === 'FAILED' || check.status === 'VIOLATION');
  if (failed.length > 0 || receipt.status === 'INVARIANT_VIOLATION') {
    return { resolved: 0, skipped: 'audit_has_findings' };
  }
  const [owner, name] = String(repo).split('/');
  if (!owner || !name || !token) return { resolved: 0, skipped: 'missing_context' };
  const data = await githubGraphql({
    fetchImpl,
    token,
    query: `query($owner:String!,$name:String!,$pr:Int!){
      repository(owner:$owner,name:$name){
        pullRequest(number:$pr){
          reviewThreads(first:100){
            nodes{ id isResolved comments(first:10){ nodes{ body path line commit{ oid } } } }
          }
        }
      }
    }`,
    variables: { owner, name, pr: prNumber },
  });
  const threads = data?.repository?.pullRequest?.reviewThreads?.nodes || [];
  const failedIds = new Set(failed.map((check) => String(check.id || '').toLowerCase()));
  let resolved = 0;
  for (const thread of threads) {
    if (thread.isResolved) continue;
    const first = thread.comments?.nodes?.[0];
    const rule = /<!-- roninos-rule:([a-zA-Z0-9_.-]+) -->/.exec(String(first?.body || ''));
    if (!rule || failedIds.has(rule[1].toLowerCase())) continue;
    const reply = await githubGraphql({
      fetchImpl,
      token,
      query: `mutation($threadId:ID!,$body:String!){
        addPullRequestReviewThreadReply(input:{pullRequestReviewThreadId:$threadId,body:$body}){ comment{ id } }
      }`,
      variables: {
        threadId: thread.id,
        body: `RoninOS no longer observes modeled rule \`${rule[1]}\` at \`${headSha || receipt.git?.headSha || 'this head'}\`. Resolving this thread. Not a safety verdict.`,
      },
    });
    if (!reply) continue;
    const done = await githubGraphql({
      fetchImpl,
      token,
      query: `mutation($threadId:ID!){ resolveReviewThread(input:{threadId:$threadId}){ thread{ isResolved } } }`,
      variables: { threadId: thread.id },
    });
    if (done) resolved += 1;
  }
  return { resolved };
}

export async function postReview({
  fetchImpl = fetch,
  token,
  repo,
  prNumber,
  receipt,
  headSha,
  checkName = DEFAULT_CHECK_NAME,
  dryRun = false,
  fileContents = {},
  publicKeyPem = null,
}) {
  if (!repo || !prNumber) throw new Error('repo and prNumber are required');
  if (!receipt) throw new Error('receipt is required');
  const prepared = await prepareReceipt({
    receipt,
    fetchImpl,
    token,
    repo,
    headSha: headSha || receipt.git?.headSha || null,
    fileContents,
    publicKeyPem,
  });
  const payload = buildReviewPayload(prepared, { headSha });
  if (dryRun) return { dryRun: true, payload };

  const failed = (prepared.checks || []).filter((check) => check.status === 'FAILED' || check.status === 'VIOLATION').length;
  const check = await upsertCheckRun({
    fetchImpl,
    token,
    repo,
    headSha: payload.commitId || headSha,
    checkName,
    conclusion: payload.conclusion,
    title: failed > 0 ? `${failed} modeled invariant finding(s)` : 'No modeled invariant violations',
    summary: payload.synthesized.summaryMarkdown,
  });

  const summary = failed === 0
    ? { posted: false, skipped: 'clean' }
    : token
      ? await upsertSummaryComment({ fetchImpl, token, repo, prNumber, body: payload.body })
      : { posted: false, error: 'missing token' };

  let review = { posted: false, skipped: true, reason: 'no inline findings' };
  if (token && payload.comments.length > 0) {
    const found = await findReview(fetchImpl, token, repo, prNumber);
    if (found.error) {
      review = { posted: false, error: found.error };
    } else if (found.existing) {
      review = { posted: true, skipped: true, id: found.existing.id, reason: 'already posted' };
    } else {
      const created = await githubFetch(
        fetchImpl,
        token,
        `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews`,
        {
          method: 'POST',
          body: JSON.stringify({
            ...(payload.commitId ? { commit_id: payload.commitId } : {}),
            body: payload.body,
            event: 'COMMENT',
            comments: payload.comments,
          }),
        },
      );
      if (created.ok) {
        review = { posted: true, id: created.data?.id || null, comments: payload.comments.length };
      } else {
        const fallbackBody = `${payload.body}\n\n### Inline findings\n\n${payload.comments
          .map((comment) => `**\`${comment.path}:${comment.line}\`**\n\n${comment.body}`)
          .join('\n\n---\n\n')}`;
        const fallback = await upsertSummaryComment({ fetchImpl, token, repo, prNumber, body: fallbackBody });
        review = { posted: fallback.posted, fallback: true, status: created.status, comments: payload.comments.length };
      }
    }
  }

  const threadResolution = token
    ? await resolveSatisfiedThreads({
        fetchImpl,
        token,
        repo,
        prNumber,
        receipt: prepared,
        headSha: payload.commitId || headSha,
      })
    : { resolved: 0, skipped: 'missing_token' };

  return {
    check,
    summary,
    review,
    resolvedThreads: threadResolution.resolved,
    conclusion: payload.conclusion,
    comments: payload.comments.length,
    suggestions: payload.comments.filter((comment) => comment.body.includes('```suggestion')).length,
  };
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--receipt') options.receipt = argv[++index];
    else if (arg === '--repo') options.repo = argv[++index];
    else if (arg === '--pr') options.prNumber = Number(argv[++index]);
    else if (arg === '--token') options.token = argv[++index];
    else if (arg === '--head') options.headSha = argv[++index];
    else if (arg === '--check-name') options.checkName = argv[++index];
    else if (arg === '--public-key') options.publicKeyPem = argv[++index];
    else if (arg === '--dry-run') options.dryRun = true;
    else if (arg === '--help' || arg === '-h') options.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    console.log(`Usage:
  node post-review.mjs --receipt roninos-receipt.json --repo owner/repo --pr 123 --token $GITHUB_TOKEN [--head SHA] [--check-name RoninOS] [--dry-run]`);
    return;
  }
  if (!options.receipt) throw new Error('--receipt is required');
  const result = await postReview({
    receipt: readJson(options.receipt),
    repo: options.repo,
    prNumber: options.prNumber,
    token: options.token || process.env.GITHUB_TOKEN || process.env.GH_TOKEN,
    headSha: options.headSha || process.env.GITHUB_SHA || null,
    checkName: options.checkName || DEFAULT_CHECK_NAME,
    dryRun: options.dryRun,
    publicKeyPem: options.publicKeyPem || null,
  });
  console.log(JSON.stringify(result, null, 2));
}

if (process.argv[1] && process.argv[1].endsWith('post-review.mjs')) {
  main().catch((error) => {
    console.error(`RoninOS review post failed: ${error.message}`);
    process.exit(1);
  });
}
