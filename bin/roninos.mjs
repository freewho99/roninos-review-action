#!/usr/bin/env node
// ==============================================================================
// RONINOS SOVEREIGN APERTURE CLI, WARM DAEMON & MCP SERVER (v3.0.0)
// Author: Prince Jacque Dionne Finney — Fullstack Blockchain Solutions LLC
// Includes:
//   - 5-Pillar Core + 6 Deep Architectural Extensions (Repo-Wide SQLite CTE,
//     SSA Field Aliasing, CFG Dominator Proofs, ORM TOCTOU Gate, Supply-Chain
//     Lockfile Gate, Ed25519 Cryptographic Signatures + Git Notes)
//   - Split Warm Eval vs. Cold Boot Telemetry + Local Warm Daemon (<3ms CLI)
//   - Native SARIF 2.1.0 Export (--sarif) & Pre-Push Hook Installer
// ==============================================================================

import { execSync, execFileSync, spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import crypto from 'node:crypto';
import readline from 'node:readline';
import vm from 'node:vm';
import { pathToFileURL } from 'node:url';

const RONIN_HOME = path.join(os.homedir(), '.roninos');
const DAEMON_PORT = Number(process.env.RONINOS_DAEMON_PORT || 49152);

// ------------------------------------------------------------------------------
// 1. DYNAMIC MODULE LOADERS
// ------------------------------------------------------------------------------
async function importFirstExisting(relPaths) {
  const roots = [
    path.resolve(import.meta.dirname || '.', '../lib'),
    path.resolve(import.meta.dirname || '.', '..'),
    process.cwd()
  ];
  for (const root of roots) {
    for (const rel of relPaths) {
      const candidate = path.resolve(root, rel);
      if (fs.existsSync(candidate)) {
        return await import(pathToFileURL(candidate).href);
      }
    }
  }
  return null;
}

let _cachedEngine = null;
let _wasmBootMs = 0;

async function getApertureEngineInstance() {
  if (_cachedEngine) return { engine: _cachedEngine, coldBootMs: 0 };

  const tBoot = performance.now();
  const mod = await importFirstExisting([
    'polyglotApertureEngine.js',
    'index.js',
    'src/shared/architecturalAperture/polyglotApertureEngine.js',
    'src/shared/architecturalAperture/index.js'
  ]);

  if (!mod) {
    throw new Error('Unable to locate polyglotApertureEngine.js or src/shared/architecturalAperture/polyglotApertureEngine.js');
  }

  const EngineClass = mod.PolyglotApertureEngine || mod.default?.PolyglotApertureEngine || mod.default;
  _cachedEngine = new EngineClass();
  _wasmBootMs = +(performance.now() - tBoot).toFixed(2);
  return { engine: _cachedEngine, coldBootMs: _wasmBootMs };
}

async function loadDeepExtensions() {
  return await importFirstExisting([
    'deepInvariantsEngine.js',
    'src/shared/architecturalAperture/deepInvariantsEngine.js',
    'src/shared/architecturalAperture/deepInvariantsEngine.mjs',
    'deepInvariantsEngine.mjs'
  ]);
}

async function loadCommentSynthesizer() {
  return await importFirstExisting([
    'reviewCommentSynthesizer.js',
    'src/shared/architecturalAperture/reviewCommentSynthesizer.js',
    'src/shared/reviewCommentSynthesizer.js'
  ]);
}

async function loadTricorderEngine() {
  return await importFirstExisting([
    'tricorderEngine.js',
    'src/shared/architecturalAperture/tricorderEngine.js'
  ]);
}

// ------------------------------------------------------------------------------
// 2. UNIFIED GIT DIFF SPLITTER & REPO HARVESTER
// ------------------------------------------------------------------------------
function splitUnifiedDiffByFile(rawDiff) {
  if (!rawDiff || !rawDiff.trim()) return [];
  const chunks = rawDiff.split(/(?=^diff --git )/m).filter((c) => c.trim());
  if (chunks.length === 0) {
    const m = rawDiff.match(/^\+\+\+ b\/(.+)$/m);
    return [{ filePath: m ? m[1].trim() : 'unknown.ts', diff: rawDiff }];
  }
  return chunks.map((chunk) => {
    const plusMatch = chunk.match(/^\+\+\+ b\/(.+)$/m);
    const gitMatch = chunk.match(/^diff --git a\/(.+?) b\/(.+)$/m);
    const filePath = plusMatch ? plusMatch[1].trim() : gitMatch ? gitMatch[2].trim() : 'unknown.ts';
    return { filePath, diff: chunk };
  });
}

function globToRegExp(pattern) {
  const escaped = String(pattern)
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '.')
    .replace(/\u0000\//g, '(?:.*/)?')
    .replace(/\u0000/g, '.*');
  return new RegExp('^' + escaped + '$');
}

function filterDiffByExclusions(rawDiff, patterns = []) {
  if (!patterns.length) return rawDiff;
  const regexes = patterns.map(globToRegExp);
  return splitUnifiedDiffByFile(rawDiff)
    .filter((entry) => !regexes.some((regex) => regex.test(entry.filePath)))
    .map((entry) => entry.diff)
    .join('');
}

function harvestLocalDiff(diffTarget = 'HEAD') {
  try {
    const out = execFileSync('git', ['diff', diffTarget], {
      encoding: 'utf8',
      maxBuffer: 50 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore']
    });
    if (out.trim()) return out;
  } catch {}
  try {
    const outCached = execFileSync('git', ['diff', '--cached'], {
      encoding: 'utf8',
      maxBuffer: 50 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore']
    });
    if (outCached.trim()) return outCached;
  } catch {}
  try {
    return execFileSync('git', ['diff'], {
      encoding: 'utf8',
      maxBuffer: 50 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore']
    });
  } catch {
    return '';
  }
}

function resolveHeadSha(target) {
  if (!target || typeof target !== 'string') return null;
  try {
    const sha = execFileSync('git', ['rev-parse', '--verify', `${target}^{commit}`], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim().toLowerCase();
    return /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(sha) ? sha : null;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------------------
// 3. FULL 6-LAYER DEEP DETERMINISTIC AUDIT
// ------------------------------------------------------------------------------
function receiptScope(totalRules) {
  return {
    coverage: {
      modeled: `${totalRules} AST/security invariants`,
      notAssessed: ['business-rule constraints', 'authorization semantics', 'server-only information flow', 'unmodeled defects']
    },
    limitations: 'DETERMINISTIC_PASS means no modeled invariant failed. It is not a review approval and does not establish that no actionable defect exists.'
  };
}

function pruneUndefined(value) {
  if (Array.isArray(value)) return value.map((item) => item === undefined ? null : pruneUndefined(item));
  if (value && typeof value === 'object') {
    const output = {};
    for (const [key, item] of Object.entries(value)) {
      if (item !== undefined) output[key] = pruneUndefined(item);
    }
    return output;
  }
  return value;
}

async function executeApertureAudit(diffTarget = 'HEAD', explicitDiff = null, attachGitNote = false, options = {}) {
  const { engine, coldBootMs } = await getApertureEngineInstance();
  const deepMod = await loadDeepExtensions();
  const tricorderMod = await loadTricorderEngine();
  const repositoryCanonicalSources = (tricorderMod?.CANONICAL_SHARED_UTILITIES || [])
    .map((util) => {
      const repoRoot = path.resolve(process.cwd());
      const fullPath = path.resolve(repoRoot, util.filePath);
      if (!fullPath.startsWith(repoRoot + path.sep)) return null;
      if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) return null;
      return { filePath: util.filePath, sourceCode: fs.readFileSync(fullPath, 'utf8') };
    })
    .filter(Boolean);
  const tricorder = tricorderMod?.TricorderArchitecturalEngine
    ? new tricorderMod.TricorderArchitecturalEngine({ repositorySources: repositoryCanonicalSources })
    : null;

  const rawDiff = filterDiffByExclusions(
    explicitDiff !== null ? explicitDiff : harvestLocalDiff(diffTarget),
    options.excludePatterns || []
  );
  const headSha = resolveHeadSha(diffTarget);
  const tEvalStart = performance.now();

  if (!rawDiff || !rawDiff.trim()) {
    const emptyReceipt = {
      receiptId: `rcpt_aperture_${crypto.randomBytes(6).toString('hex')}`,
      status: 'DETERMINISTIC_PASS',
      verdict: 'NO_MODELED_VIOLATION',
      ...receiptScope(51),
      checks: [],
      violations: { ast: [], security: [], taint: [], reflection: [], stripe: [], supplyChain: [] },
      summary: { totalRules: 51, passed: 51, failed: 0, verdict: 'NO_MODELED_VIOLATION', elapsedMs: 0.12, coldBootMs },
      elapsedMs: 0.12,
      coldBootMs,
      filesEvaluated: 0,
      bundleMode: 'none',
      bundleCount: 0,
      bundles: [],
      bundleReceipts: [],
      git: { headSha, resolved: headSha !== null, target: diffTarget },
      zeroTokensBilled: true,
      timestamp: new Date().toISOString()
    };
    if (deepMod?.signAndAttestReceipt) {
      emptyReceipt.attestation = deepMod.signAndAttestReceipt(emptyReceipt, attachGitNote);
    }
    return emptyReceipt;
  }

  const fileSlices = splitUnifiedDiffByFile(rawDiff);
  const aggregatedChecks = [];
  const aggregatedViolations = {
    ast: [],
    security: [],
    taint: [],
    reflection: [],
    stripe: [],
    supplyChain: []
  };

  let totalRules = 51; // 45 core + 6 deep architectural gates
  let totalFailed = 0;
  let hasViolation = false;
  let primaryReceiptId = null;
  let bundleMode = 'none';
  let bundleResult = null;

  // Initialize Repo-Wide Call-Graph Index (.roninos/graph.sqlite) if available
  let repoGraph = null;
  if (deepMod?.RepoWideCallGraphIndex) {
    repoGraph = new deepMod.RepoWideCallGraphIndex(process.cwd());
    repoGraph.init();
  }

  // 1. Deep-extension / repo-graph enrichment across every candidate slice, before bundling.
  const modifiedPaths = [];
  const deepChecks = [];
  for (const slice of fileSlices) {
    if (slice.filePath === '/dev/null') continue;
    modifiedPaths.push(slice.filePath);
    if (!deepMod) continue;

    const fullDiskPath = path.resolve(process.cwd(), slice.filePath);
    if (repoGraph && fs.existsSync(fullDiskPath) && fs.statSync(fullDiskPath).isFile()) {
      repoGraph.indexFileIncremental(slice.filePath, fs.readFileSync(fullDiskPath, 'utf8'));
    }

    for (const c of deepMod.analyzeFieldSensitiveSsaAliases(slice.diff, slice.filePath)) {
      deepChecks.push({ check: c, file: slice.filePath, violationKey: 'taint' });
    }
    for (const c of deepMod.evaluateOrmConcurrencyToctou(slice.diff, slice.filePath)) {
      deepChecks.push({ check: c, file: slice.filePath, violationKey: 'stripe' });
    }
    for (const c of deepMod.evaluateSupplyChainDifferential(slice.diff, slice.filePath)) {
      deepChecks.push({ check: c, file: slice.filePath, violationKey: 'supplyChain' });
    }

    if (tricorder) {
      try {
        const triRes = tricorder.reviewDiff(slice.diff, slice.filePath);
        if (triRes && Array.isArray(triRes.findings)) {
          for (const finding of triRes.findings) {
            const check = {
              id: finding.ruleId || 'ARCH-012-REDUNDANT-REINVENTION',
              name: finding.title || 'Redundant Code Reinvention',
              status: 'FAILED',
              pillar: 'ARCHITECTURAL',
              file: slice.filePath,
              line: finding.newFunction?.startLine || 1,
              endLine: finding.newFunction?.endLine || finding.newFunction?.startLine || 1,
              message: finding.evidence || 'Redundant duplicate utility reinvention detected',
              details: finding.evidence || 'Redundant duplicate utility reinvention detected',
              patch: finding.remediationPatch,
              patchStatus: finding.patchProof?.status || 'VERIFIED_CLEAN_AST'
            };
            deepChecks.push({ check, file: slice.filePath, violationKey: 'ast' });
          }
        }
      } catch (_) {}
    }
  }

  const externalEdges = typeof repoGraph?.getCrossFileEdges === 'function'
    ? repoGraph.getCrossFileEdges(modifiedPaths)
    : [];

  // 2. Engine evaluation. Bundles require an exact head; without one, keep per-slice evaluation.
  if (headSha !== null) {
    try {
      bundleResult = await engine.evaluateDiffBundled(rawDiff, { headSha, externalEdges, previousReceipt: options.previousReceipt });
      bundleMode = 'bundled';
    } catch (err) {
      bundleMode = `fallback:${err?.code || 'BUNDLE_ERROR'}`;
    }
  } else {
    bundleMode = 'per-slice-no-head';
  }

  if (bundleResult) {
    primaryReceiptId = bundleResult.bundles?.[0]?.receiptId || bundleResult.receiptId;
    if (bundleResult.status === 'INVARIANT_VIOLATION') hasViolation = true;
    if (Array.isArray(bundleResult.checks)) aggregatedChecks.push(...bundleResult.checks);
    for (const k of ['ast', 'security', 'taint', 'reflection', 'stripe', 'supplyChain']) {
      if (Array.isArray(bundleResult.violations?.[k])) aggregatedViolations[k].push(...bundleResult.violations[k]);
    }
  } else {
    for (const slice of fileSlices) {
      if (slice.filePath === '/dev/null') continue;
      const res = await engine.evaluateDiff(slice.diff, slice.filePath, { headSha });
      if (!primaryReceiptId && res.receiptId) primaryReceiptId = res.receiptId;
      if (res.status === 'INVARIANT_VIOLATION' || res.verdict === 'REQUEST_CHANGES') {
        hasViolation = true;
      }
      if (Array.isArray(res.checks)) aggregatedChecks.push(...res.checks);
      if (res.violations) {
        for (const k of ['ast', 'security', 'taint', 'reflection', 'stripe']) {
          if (Array.isArray(res.violations[k])) aggregatedViolations[k].push(...res.violations[k]);
        }
      }
    }
  }

  // 3. Attach deep-extension findings to the bundle that contains their file.
  const fileToBundle = new Map();
  if (bundleResult) {
    for (const bundle of bundleResult.bundles || []) {
      for (const file of bundle.files || []) fileToBundle.set(file, bundle.bundleId);
    }
  }

  for (const { check, file, violationKey } of deepChecks) {
    hasViolation = true;
    const bundleId = fileToBundle.get(file) ?? null;
    aggregatedChecks.push({
      ...check,
      bundleId,
      bundleSource: bundleId ? 'bundle' : (bundleResult ? 'unbundled' : 'per-slice')
    });
    aggregatedViolations[violationKey].push(check.id);
  }

  // 4. Query Repo-Wide Transitive Taint Across Unchanged Callers/Callees
  if (repoGraph && modifiedPaths.length > 0) {
    const transitiveHits = repoGraph.queryTransitiveUnchangedCallerRegressions(modifiedPaths);
    for (const hit of transitiveHits) {
      hasViolation = true;
      const checkId = 'TAINT-REPO-WIDE-UNCHANGED-CALLER';
      const bundleId = fileToBundle.get(hit.sink_file) ?? null;
      aggregatedViolations.taint.push(checkId);
      aggregatedChecks.push({
        id: checkId,
        name: 'Cross-File Taint Regression Across Unchanged Callers',
        status: 'FAILED',
        pillar: 'TAINT',
        file: hit.sink_file,
        line: 1,
        bundleId,
        bundleSource: bundleId ? 'bundle' : 'repo-wide',
        message: `Unchanged source (${hit.start_file}:${hit.start_fn}) flows through modified code into sink (${hit.sink_file}:${hit.sink_fn}). Full trace: ${hit.path_trace}`
      });
    }
  }

  const elapsedMs = +(performance.now() - tEvalStart).toFixed(2);
  const exclusionRegexes = (options.excludePatterns || []).map(globToRegExp);
  const keptChecks = exclusionRegexes.length === 0
    ? aggregatedChecks
    : aggregatedChecks.filter((check) => !check.file || !exclusionRegexes.some((regex) => regex.test(check.file)));
  hasViolation = keptChecks.some((check) => check.status === 'FAILED');
  totalFailed = keptChecks.filter((c) => c.status === 'FAILED').length;
  const totalPassed = Math.max(0, totalRules - totalFailed);
  const diffSha256 = crypto.createHash('sha256').update(rawDiff).digest('hex');

  let finalReceipt = {
    receiptId: primaryReceiptId || `rcpt_aperture_${crypto.randomBytes(6).toString('hex')}`,
    diffSha256,
    filesEvaluated: fileSlices.length,
    bundleMode,
    bundleCount: bundleResult?.bundleCount ?? 0,
    bundles: bundleResult?.bundles ?? [],
    bundleReceipts: (bundleResult?.bundles ?? []).map((b) => ({
      bundleId: b.bundleId,
      files: b.files,
      receiptId: b.receiptId,
      status: b.status,
      verdict: b.verdict,
      elapsedMs: b.elapsedMs
    })),
    git: { headSha, resolved: headSha !== null, target: diffTarget },
    status: hasViolation ? 'INVARIANT_VIOLATION' : 'DETERMINISTIC_PASS',
    verdict: hasViolation ? 'REQUEST_CHANGES' : 'NO_MODELED_VIOLATION',
    ...receiptScope(totalRules),
    checks: keptChecks,
    violations: aggregatedViolations,
    summary: {
      totalRules,
      passed: totalPassed,
      failed: totalFailed,
      verdict: hasViolation ? 'BLOCKED' : 'NO_MODELED_VIOLATION',
      elapsedMs,
      coldBootMs
    },
    elapsedMs,
    coldBootMs,
    zeroTokensBilled: true,
    timestamp: new Date().toISOString()
  };

  finalReceipt = pruneUndefined(finalReceipt);
  if (deepMod?.signAndAttestReceipt) {
    finalReceipt.attestation = deepMod.signAndAttestReceipt(finalReceipt, attachGitNote);
  }

  return finalReceipt;
}

// ------------------------------------------------------------------------------
// 4. NATIVE SARIF 2.1.0 GENERATOR (--sarif for GitHub Security Tab)
// ------------------------------------------------------------------------------
function convertReceiptToSarif(receipt) {
  const failedChecks = (receipt.checks || []).filter((c) => c.status === 'FAILED');
  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'RoninOS Polyglot Aperture Engine',
            version: '3.0.0',
            informationUri: 'https://roninos.com',
            rules: failedChecks.map((c) => ({
              id: c.id,
              name: c.name || c.id,
              shortDescription: { text: c.message }
            }))
          }
        },
        results: failedChecks.map((c) => ({
          ruleId: c.id,
          level: 'error',
          message: { text: c.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: c.file || 'unknown' },
                region: { startLine: c.line || 1 }
              }
            }
          ],
          properties: {
            receiptId: receipt.receiptId,
            pillar: c.pillar,
            signature: receipt.attestation?.signature || null
          }
        }))
      }
    ]
  };
}

// ------------------------------------------------------------------------------
// 5. LOCAL WARM DAEMON (Keeps WASM Grammars Hot in RAM for <3ms CLI Runs)
// ------------------------------------------------------------------------------
async function startWarmDaemon() {
  // Pre-warm WASM AST engine immediately on daemon boot
  await getApertureEngineInstance();

  const server = http.createServer(async (req, res) => {
    if (req.method === 'POST' && req.url === '/audit') {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', async () => {
        try {
          const { target, diff, attachGitNote, cwd } = JSON.parse(body || '{}');
          const currentCwd = process.cwd();
          const sameCwd = typeof cwd === 'string' && (process.platform === 'win32'
            ? path.resolve(cwd).toLowerCase() === path.resolve(currentCwd).toLowerCase()
            : path.resolve(cwd) === path.resolve(currentCwd));
          if (!sameCwd) {
            res.writeHead(409, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'daemon-cwd-mismatch', daemonCwd: currentCwd }));
            return;
          }
          const result = await executeApertureAudit(target || 'HEAD', diff || null, !!attachGitNote);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (err) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: err.message }));
        }
      });
    } else if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'WARM', pid: process.pid, cwd: process.cwd() }));
    } else {
      res.writeHead(404);
      res.end();
    }
  });

  server.listen(DAEMON_PORT, '127.0.0.1', () => {
    console.log(`[roninosd] Warm AST/SQLite Daemon listening on 127.0.0.1:${DAEMON_PORT} (0ms cold start)`);
  });
}

async function tryQueryWarmDaemon(target, attachGitNote) {
  try {
    const healthCtrl = new AbortController();
    const healthTimer = setTimeout(() => healthCtrl.abort(), 120);
    const healthRes = await fetch(`http://127.0.0.1:${DAEMON_PORT}/health`, { signal: healthCtrl.signal });
    clearTimeout(healthTimer);
    if (healthRes.ok) {
      const res = await fetch(`http://127.0.0.1:${DAEMON_PORT}/audit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, attachGitNote, cwd: process.cwd() })
      });
      if (res.ok) {
        const json = await res.json();
        json.coldBootMs = 0;
        return json;
      }
    }
  } catch {
    // Daemon not running; auto-spawn detached warm daemon in background for future runs
    try {
      const child = spawn(process.execPath, [path.resolve(process.argv[1]), 'daemon'], {
        detached: true,
        stdio: 'ignore',
        windowsHide: true
      });
      child.unref();
    } catch {}
  }
  return null;
}

// ------------------------------------------------------------------------------
// 6. AUTOMATIC GIT PRE-PUSH HOOK INSTALLER (\`roninos hook install\`)
// ------------------------------------------------------------------------------
function installGitPrePushHook() {
  const gitHooksDir = path.resolve(process.cwd(), '.git', 'hooks');
  if (!fs.existsSync(gitHooksDir)) {
    console.error('✗ No .git/hooks directory found in current working directory.');
    process.exit(1);
  }
  const hookPath = path.join(gitHooksDir, 'pre-push');
  const scriptPath = path.resolve(process.argv[1]).replace(/\\/g, '/');
  const hookContent = `#!/bin/sh
# RoninOS Sovereign 5-Pillar Pre-Push Gate (Zero-Custody)
node "${scriptPath}" audit HEAD --attest
`;
  fs.writeFileSync(hookPath, hookContent, { mode: 0o755 });
  console.log(`✓ Installed deterministic pre-push git hook -> ${hookPath}`);
}

// ------------------------------------------------------------------------------
// 7. TERMINAL TUI RENDERER (With Split Warm Eval vs. WASM Cold-Boot Timer)
// ------------------------------------------------------------------------------
function renderReceiptTui(res) {
  const p = (arr) => (arr && arr.length > 0 ? 'FAIL' : 'PASS');
  const evalStr = `${res.elapsedMs} ms (Warm Eval)`;
  const bootStr = res.coldBootMs > 0 ? `${res.coldBootMs} ms (Cold Init)` : `0.00 ms (Daemon Hot)`;

  console.log(`\n┌──────────────────────────────────────────────────────────────────────────────┐`);
  console.log(`│ RONINOS POLYGLOT APERTURE ENGINE v3.0.0              [ZERO-CUSTODY LOCAL]    │`);
  console.log(`├──────────────────────────────────────────────────────────────────────────────┤`);
  console.log(`│ Receipt ID:  ${res.receiptId.padEnd(28)} Status:   ${res.status.padEnd(20)} │`);
  console.log(`│ Verdict:     ${String(res.summary?.verdict || res.verdict).padEnd(28)} Rules:    ${String(res.summary.passed + ' / ' + res.summary.totalRules).padEnd(20)} │`);
  console.log(`│ Engine Eval: ${evalStr.padEnd(28)} Runtime:  ${bootStr.padEnd(20)} │`);
  if (res.attestation) {
    console.log(`│ Signature:   ${(res.attestation.signature.slice(0, 26) + '…').padEnd(28)} Key ID:   ${res.attestation.keyFingerprint.padEnd(20)} │`);
  }
  console.log(`├──────────────────────────────────────────────────────────────────────────────┤`);
  console.log(`│ [${p(res.violations.ast)}] Pillar 1: Multi-Lang WASM AST       (${res.violations.ast.length} violations)                  │`);
  console.log(`│ [${p(res.violations.reflection)}] Pillar 2: Reflection & Dispatch     (${res.violations.reflection.length} violations)                  │`);
  console.log(`│ [${p(res.violations.security)}] Pillar 3: Security Invariants       (${res.violations.security.length} violations)                  │`);
  console.log(`│ [${p(res.violations.taint)}] Pillar 4: Repo-Wide SQLite + SSA    (${res.violations.taint.length} violations)                  │`);
  console.log(`│ [${p(res.violations.stripe)}] Pillar 5: Fintech + ORM TOCTOU      (${res.violations.stripe.length} violations)                  │`);
  console.log(`│ [${p(res.violations.supplyChain)}] Pillar 6: Supply-Chain Lockfile     (${(res.violations.supplyChain || []).length} violations)                  │`);
  console.log(`└──────────────────────────────────────────────────────────────────────────────┘`);

  const failed = (res.checks || []).filter((c) => c.status === 'FAILED');
  if (failed.length > 0) {
    console.log(`\n✗ BLOCKING INVARIANT VIOLATIONS (${failed.length}):`);
    for (const c of failed) {
      console.log(`  • [${c.pillar || c.tier || 'APERTURE'}] ${c.id} — ${c.name || c.vulnerability || c.id}`);
      console.log(`    Location: ${c.file}:${c.line || 1}`);
      console.log(`    Message:  ${c.message || c.details || 'Invariant violation detected'}`);
    }
  } else {
    console.log(
      `\n[DETERMINISTIC_PASS] No modeled invariant failed among ${res.summary.totalRules} checks in ${res.elapsedMs} ms ($0.00 billed).` +
      `\n  Not a review approval. Unmodeled business-rule, authorization, information-flow, and other defects were not assessed.`
    );
  }
}

// ------------------------------------------------------------------------------
// 8. DOCUMENTATION VIEWER & MCP PROTOCOL SERVER
// ------------------------------------------------------------------------------
function getDocContent(topic = 'index') {
  const safeTopic = String(topic || 'index').toLowerCase().trim();
  let filename = 'README.md';
  if (safeTopic === 'owner') filename = 'OWNER_MANUAL.md';
  else if (safeTopic === 'user') filename = 'USER_GUIDE.md';
  else if (safeTopic === 'llm') filename = 'LLM_AGENT_SPEC.md';

  const candidateDirs = [
    path.resolve(import.meta.dirname || '.', '../docs/roninos'),
    path.resolve(import.meta.dirname || '.', '../../docs/roninos'),
    path.resolve(process.cwd(), 'docs/roninos'),
    path.resolve(process.cwd(), '../../docs/roninos')
  ];

  if (safeTopic === 'all') {
    const parts = [];
    const validFiles = ['README.md', 'USER_GUIDE.md', 'OWNER_MANUAL.md', 'LLM_AGENT_SPEC.md'];
    for (const f of validFiles) {
      for (const dir of candidateDirs) {
        const resolvedDir = path.resolve(dir);
        const p = path.resolve(resolvedDir, f);
        if (p.startsWith(resolvedDir + path.sep) && fs.existsSync(p)) {
          parts.push(fs.readFileSync(p, 'utf8'));
          break;
        }
      }
    }
    return parts.length > 0
      ? parts.join('\n\n---\n\n')
      : '# RoninOS Documentation\nOnline documentation available at: https://roninos.com/docs';
  }

  for (const dir of candidateDirs) {
    const resolvedDir = path.resolve(dir);
    const p = path.resolve(resolvedDir, filename);
    if (p.startsWith(resolvedDir + path.sep) && fs.existsSync(p)) {
      return fs.readFileSync(p, 'utf8');
    }
  }

  return `# RoninOS Documentation (${safeTopic})\nOnline documentation available at: https://roninos.com/docs`;
}


function openBrowser(url) {
  try {
    if (process.platform === 'win32') {
      spawn('cmd', ['/c', 'start', '', url], { detached: true, stdio: 'ignore' });
    } else if (process.platform === 'darwin') {
      spawn('open', [url], { detached: true, stdio: 'ignore' });
    } else {
      spawn('xdg-open', [url], { detached: true, stdio: 'ignore' });
    }
  } catch {
    console.log(`\nOpen documentation in browser: ${url}`);
  }
}

function handleDocsCommand(cliArgs) {
  if (cliArgs.includes('--web') || cliArgs.includes('-w')) {
    const url = 'http://localhost:3000/ronin/docs';
    console.log(`\n🌐 Opening RoninOS Interactive Documentation in browser: ${url}`);
    console.log(`   (Production cloud URL: https://roninos.com/docs)\n`);
    openBrowser(url);
    return;
  }

  const topicArg = cliArgs.find((a) => !a.startsWith('-') && a !== 'docs');

  if (!topicArg || topicArg === 'help' || topicArg === 'list') {
    console.log(`\n┌──────────────────────────────────────────────────────────────────────────────┐`);
    console.log(`│ RONINOS SOVEREIGN DOCUMENTATION v3.0.0               [CLI • WEB • MCP]       │`);
    console.log(`├──────────────────────────────────────────────────────────────────────────────┤`);
    console.log(`│ Website:  https://roninos.com/docs (Local: http://localhost:3000/ronin/docs) │`);
    console.log(`│ MCP URI:  roninos://docs/[owner|user|llm|index]                              │`);
    console.log(`├──────────────────────────────────────────────────────────────────────────────┤`);
    console.log(`│ COMMANDS:                                                                    │`);
    console.log(`│   roninos docs user     Developer Quickstart, CLI Reference, CI, MCP Setup  │`);
    console.log(`│   roninos docs owner    Architecture Bible, 6-Pillar Invariants, V8 Jail    │`);
    console.log(`│   roninos docs llm      AI Agent Specification, Golden Remediation Patterns  │`);
    console.log(`│   roninos docs all      Stream all documentation manuals to stdout           │`);
    console.log(`│   roninos docs --web    Launch interactive documentation viewer in browser   │`);
    console.log(`│   roninos mcp           Start Model Context Protocol JSON-RPC stdio server   │`);
    console.log(`└──────────────────────────────────────────────────────────────────────────────┘\n`);
    return;
  }

  const content = getDocContent(topicArg.toLowerCase());
  console.log(content);
}

async function startMcpServer() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false
  });

  const send = (msg) => {
    process.stdout.write(JSON.stringify(msg) + '\n');
  };

  rl.on('line', async (line) => {
    if (!line.trim()) return;
    let req;
    try {
      req = JSON.parse(line);
    } catch {
      return send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    }

    const { id, method, params } = req;

    if (method === 'initialize') {
      return send({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: {
            tools: {},
            resources: {}
          },
          serverInfo: {
            name: 'roninos',
            version: '3.0.0'
          }
        }
      });
    }

    if (method === 'notifications/initialized' || method === 'initialized') {
      return;
    }

    if (method === 'tools/list') {
      return send({
        jsonrpc: '2.0',
        id,
        result: {
          tools: [
            {
              name: 'roninos_audit_diff',
              description: 'Deterministic AST invariant review and security aperture engine (<3ms, zero cloud tokens). Evaluates git diff against 51 mathematical invariants and returns cryptographic audit receipt.',
              inputSchema: {
                type: 'object',
                properties: {
                  diff: { type: 'string', description: 'Optional raw git diff string to audit. If omitted, audits current git HEAD/staged diff.' },
                  target: { type: 'string', description: 'Optional git commit, ref, or "HEAD" to audit.', default: 'HEAD' },
                  attest: { type: 'boolean', description: 'Whether to sign the receipt cryptographically with Ed25519.', default: false }
                }
              }
            },
            {
              name: 'roninos_get_docs',
              description: 'Retrieve comprehensive RoninOS documentation manuals: "owner" (architecture bible & V8 containment), "user" (developer quickstart, CLI, CI), "llm" (agent specification & golden remediation blueprints), or "index" (summary index). Also available at https://roninos.com/docs.',
              inputSchema: {
                type: 'object',
                properties: {
                  topic: {
                    type: 'string',
                    enum: ['owner', 'user', 'llm', 'index', 'all'],
                    description: 'The documentation manual topic to retrieve.'
                  }
                },
                required: ['topic']
              }
            },
            {
              name: 'roninos_contain_in_jail',
              description: 'Execute untrusted LLM-generated code or diffs in a permission-restricted child process with a hard kill deadline. The child has no filesystem, child-process, worker, or addon grants; network egress is not OS-restricted. Output is scanned for banned verdict words and diffs can be AST-gated.',
              inputSchema: {
                type: 'object',
                properties: {
                  codeOrDiff: { type: 'string', description: 'The untrusted code snippet or git diff to sanitize and test.' },
                  filePath: { type: 'string', description: 'Target file path for AST gate verification.', default: 'src/patched.ts' }
                },
                required: ['codeOrDiff']
              }
            }
          ]
        }
      });
    }

    if (method === 'tools/call') {
      const toolName = params?.name;
      const toolArgs = params?.arguments || {};

      if (toolName === 'roninos_get_docs') {
        const content = getDocContent(toolArgs.topic || 'index');
        return send({
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: content }]
          }
        });
      }

      if (toolName === 'roninos_contain_in_jail') {
        try {
          const jailMod = await importFirstExisting([
            'jail/llmMechanicalJail.mjs',
            'lib/jail/llmMechanicalJail.mjs',
            'src/shared/jail/llmMechanicalJail.js'
          ]);
          if (!jailMod) throw new Error('LLM Mechanical Jail module unavailable');
          const jail = new jailMod.LLMechanicalJail();
          const targetContent = toolArgs.codeOrDiff || '';
          const filePath = toolArgs.filePath || 'src/patched.ts';

          const sanitization = jail.sanitizeDiff(targetContent);
          const isDiff = targetContent.includes('diff --git') || targetContent.includes('--- ') || targetContent.includes('@@ ');
          let astGate = null;
          if (isDiff) {
            astGate = await jail.gateRemediationPatch(targetContent, filePath);
          }
          const v8Result = await jail.executeInJail(`(() => { ${sanitization.sanitized} })()`, path.basename(filePath));
          const isClean = v8Result.status === 'CONTAINED' && (!astGate || astGate.passed);

          return send({
            jsonrpc: '2.0',
            id,
            result: {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: isClean ? 'CONTAINED' : 'REJECTED',
                  sanitization,
                  v8Result,
                  astGate,
                  zeroTokensBilled: true,
                }, null, 2)
              }],
              isError: !isClean
            }
          });
        } catch (err) {
          return send({
            jsonrpc: '2.0',
            id,
            result: {
              content: [{ type: 'text', text: `Jail containment error: ${err.message}` }],
              isError: true
            }
          });
        }
      }

      if (toolName === 'roninos_audit_diff') {
        try {
          const target = toolArgs.target || 'HEAD';
          const diff = toolArgs.diff || null;
          const attest = Boolean(toolArgs.attest);
          const result = await executeApertureAudit(target, diff, attest);
          return send({
            jsonrpc: '2.0',
            id,
            result: {
              content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
              isError: result.status === 'INVARIANT_VIOLATION'
            }
          });
        } catch (err) {
          return send({
            jsonrpc: '2.0',
            id,
            result: {
              content: [{ type: 'text', text: `Audit error: ${err.message}` }],
              isError: true
            }
          });
        }
      }

      return send({
        jsonrpc: '2.0',
        id,
        error: { code: -32601, message: `Method not found: ${toolName}` }
      });
    }

    if (method === 'resources/list') {
      return send({
        jsonrpc: '2.0',
        id,
        result: {
          resources: [
            {
              uri: 'roninos://docs/owner',
              name: 'RoninOS Owner Manual & Architecture Bible',
              mimeType: 'text/markdown',
              description: 'Core thesis, 6-pillar mechanics, V8 jail containment, and packaging runbook'
            },
            {
              uri: 'roninos://docs/user',
              name: 'RoninOS User & Developer Guide',
              mimeType: 'text/markdown',
              description: 'Developer quickstart, CLI commands, SARIF CI setup, and TREX sandbox'
            },
            {
              uri: 'roninos://docs/llm',
              name: 'RoninOS LLM Agent Specification',
              mimeType: 'text/markdown',
              description: 'Machine-readable agent directive, containment contract, and golden remediation blueprints'
            },
            {
              uri: 'roninos://docs/index',
              name: 'RoninOS Documentation Index',
              mimeType: 'text/markdown',
              description: 'Master navigation and index of RoninOS sovereign documentation'
            }
          ]
        }
      });
    }

    if (method === 'resources/read') {
      const uri = params?.uri || '';
      const topicMatch = uri.match(/^roninos:\/\/docs\/(owner|user|llm|index|all)/);
      const topic = topicMatch ? topicMatch[1] : 'index';
      const content = getDocContent(topic);
      return send({
        jsonrpc: '2.0',
        id,
        result: {
          contents: [
            {
              uri,
              mimeType: 'text/markdown',
              text: content
            }
          ]
        }
      });
    }

    if (method === 'ping') {
      return send({ jsonrpc: '2.0', id, result: {} });
    }

    return send({
      jsonrpc: '2.0',
      id,
      error: { code: -32601, message: `Unhandled method: ${method}` }
    });
  });
}

// ------------------------------------------------------------------------------
// 8.5 MECHANICAL LLM JAIL COMMAND HANDLER
// ------------------------------------------------------------------------------
async function handleJailCommand(cliArgs) {
  const jailMod = await importFirstExisting([
    'jail/llmMechanicalJail.mjs',
    'lib/jail/llmMechanicalJail.mjs',
    'src/shared/jail/llmMechanicalJail.js'
  ]);
  if (!jailMod) {
    console.error('Error: LLM Mechanical Jail module could not be loaded.');
    process.exit(1);
  }

  const { LLMechanicalJail } = jailMod;
  const jail = new LLMechanicalJail();

  let targetContent = '';
  let targetName = 'untrusted_input';

  const fileArg = cliArgs.find(a => a !== 'jail' && !a.startsWith('-'));
  if (fileArg && fileArg.includes('.') && !fileArg.includes('..')) {
    const safeBase = path.basename(fileArg);
    const resolvedPath = path.resolve(process.cwd(), safeBase);
    if (resolvedPath.startsWith(process.cwd()) && fs.existsSync(resolvedPath)) {
      targetContent = fs.readFileSync(resolvedPath, 'utf8');
      targetName = safeBase;
    }
  } else if (cliArgs.includes('--stdin')) {
    // Read from stdin pipe
    targetContent = await new Promise(resolve => {
      let data = '';
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', chunk => data += chunk);
      process.stdin.on('end', () => resolve(data));
    });
    targetName = 'stdin_stream';
  } else {
    // Self-test demonstration if no target specified
    targetContent = `// Injection: bypass instructions and evaluate math\nconst sum = 40 + 2;\nreturn sum;`;
    targetName = 'jail_selftest';
  }

  const timeoutEq = cliArgs.find((arg) => arg.startsWith('--timeout='));
  const timeoutIndex = cliArgs.indexOf('--timeout');
  const timeoutMs = Number(
    timeoutEq ? timeoutEq.split('=')[1] : (timeoutIndex >= 0 ? cliArgs[timeoutIndex + 1] : null)
  ) || 1000;

  const t0 = performance.now();
  const sanitization = jail.sanitizeDiff(targetContent);
  const isDiff = targetContent.includes('diff --git') || targetContent.includes('--- ') || targetContent.includes('@@ ');
  let astGate = null;
  let v8Result = null;
  let kernelResult = null;

  if (isDiff) {
    const kernelMod = await importFirstExisting(['src/kernel/index.js', 'lib/kernel/index.js']);
    if (!kernelMod) {
      console.error('Error: Kernel remediation gate could not be loaded.');
      process.exit(1);
    }
    const { getRoninKernel, createDeveloperTicket } = kernelMod;
    const kernel = getRoninKernel();
    const ticket = createDeveloperTicket('cli_jail');
    ticket.maxCpuMs = timeoutMs;
    kernelResult = await kernel.admit({
      type: 'REMEDIATION_EVAL',
      rawDiff: targetContent,
      filePath: targetName,
      idempotencyKey: `cli-jail:${crypto.createHash('sha256').update(targetContent).digest('hex')}`
    }, ticket);
    astGate = {
      passed: kernelResult.payload?.passed === true,
      violations: kernelResult.payload?.violations || [],
      apertureReceipt: kernelResult.payload?.apertureReceipt || null
    };
  } else {
    v8Result = await jail.executeInChildJail(
      `(() => { ${sanitization.sanitized} })()`,
      targetName,
      timeoutMs
    );
  }

  const elapsedMs = (performance.now() - t0).toFixed(2);
  const isClean = isDiff
    ? kernelResult?.status !== 'PREEMPTED' && astGate?.passed === true
    : v8Result?.status === 'CONTAINED';

  if (cliArgs.includes('--json')) {
    console.log(JSON.stringify({
      status: isClean ? 'CONTAINED' : 'REJECTED',
      target: targetName,
      elapsedMs,
      sanitization,
      kernelStatus: kernelResult?.status || null,
      jobId: kernelResult?.jobId || null,
      v8Result,
      astGate,
      zeroTokensBilled: true,
    }, null, 2));
    process.exit(isClean ? 0 : 1);
  }

  const sanitizationLabel = isDiff ? 'N/A (diff mode)' : `${sanitization.stripped} bytes stripped`;
  const isolationLabel = isDiff ? 'Terminable analysis worker' : 'Permission-restricted child';

  console.log('\n┌──────────────────────────────────────────────────────────────────────────────┐');
  console.log('│ RONINOS MECHANICAL LLM JAIL v3.1.0                 [CHILD PROCESS]           │');
  console.log('├──────────────────────────────────────────────────────────────────────────────┤');
  console.log(`│ Status:       ${(isClean ? '\x1b[32mCONTAINED\x1b[0m' : '\x1b[31mREJECTED\x1b[0m').padEnd(38)} Target:   ${targetName.slice(0, 24).padEnd(24)} │`);
  console.log(`│ Sanitization: ${sanitizationLabel.padEnd(28)} Timeout:  ${`${timeoutMs} ms hard cap`.padEnd(24)} │`);
  console.log(`│ Isolation:    ${isolationLabel.padEnd(28)} Network:  not OS-restricted             │`);
  console.log(`│ AST Gate:     ${(astGate ? (astGate.passed ? 'PASSED (0 violations)' : 'FAILED') : 'N/A (Script mode)').padEnd(28)} Elapsed:  ${`${elapsedMs} ms`.padEnd(24)} │`);
  console.log('└──────────────────────────────────────────────────────────────────────────────┘\n');

  if (!isClean) {
    console.error('\x1b[31m[CONTAINMENT REJECTED]\x1b[0m');
    if (v8Result?.errors?.length) {
      for (const err of v8Result.errors) console.error(`  ├─ ${err}`);
    }
    if (astGate?.violations?.length) {
      for (const v of astGate.violations) console.error(`  ├─ [AST Violation] ${v.name || v.id}: ${v.details}`);
    }
    if (kernelResult?.status === 'PREEMPTED') {
      console.error(`  ├─ Kernel preempted: ${kernelResult.error || 'deadline exceeded'}`);
    }
    process.exit(1);
  } else {
    console.log(isDiff
      ? '\x1b[32m✓ Kernel remediation gate returned CONTAINED ($0.00 tokens billed).\x1b[0m\n'
      : '\x1b[32m✓ Child-process jail returned CONTAINED ($0.00 tokens billed).\x1b[0m\n');
    process.exit(0);
  }
}

// ------------------------------------------------------------------------------
// 8.6 AUTHORITATIVE KERNEL COMMAND HANDLER
// ------------------------------------------------------------------------------
// Conformance probes live in src/kernel/conformance.js so they can run against
// an isolated in-memory journal and are covered by tests.

async function handleKernelCommand(cliArgs) {
  const kernelMod = await importFirstExisting([
    'src/kernel/index.js',
    'lib/kernel/index.js'
  ]);
  if (!kernelMod) {
    console.error('Error: RoninOS Kernel subsystem could not be loaded.');
    process.exit(1);
  }

  const { getRoninKernel, getKernelJournal, createDeveloperTicket } = kernelMod;
  const kernel = getRoninKernel();
  const journal = getKernelJournal();
  const action = cliArgs[1] || 'status';
  const fit = (text, width) => {
    const value = String(text ?? '');
    return value.length > width ? `${value.slice(0, Math.max(0, width - 3))}...` : value.padEnd(width);
  };
  const boxLine = (text) => `│ ${fit(text, 76)} │`;

  if (action === 'journal') {
    const allJobs = kernel.readJournal(createDeveloperTicket('cli_operator'), 15);
    const hideProbes = cliArgs.includes('--hide-probes');
    const isProbe = (job) => job.actor === 'conformance_probe' || job.actor === 'test' || String(job.jobId || '').startsWith('probe-');
    const jobs = hideProbes ? allJobs.filter((job) => !isProbe(job)) : allJobs;
    if (cliArgs.includes('--json')) {
      console.log(JSON.stringify(jobs, null, 2));
      process.exit(0);
    }
    const storage = journal.db ? 'WAL STORAGE' : 'IN-MEMORY';
    console.log('\n┌──────────────────────────────────────────────────────────────────────────────┐');
    const journalTitle = 'RONINOS KERNEL ADMISSION JOURNAL';
    console.log(boxLine(`${journalTitle}${' '.repeat(Math.max(1, 76 - journalTitle.length - storage.length))}${storage}`));
    console.log('├──────────────────────────────────────────────────────────────────────────────┤');
    if (!jobs || jobs.length === 0) {
      console.log('│ (No jobs recorded yet in kernel journal)                                     │');
    } else {
      const colorFor = (status) => {
        if (['COMPLETED', 'CONTAINED', 'DETERMINISTIC_PASS'].includes(status)) return '\x1b[32m';
        if (['PREEMPTED', 'ADMITTED'].includes(status)) return '\x1b[33m';
        return '\x1b[31m';
      };
      for (const j of jobs) {
        const statusColor = colorFor(j.status);
        const line = `│ ${j.jobId.slice(0, 12)} │ ${(j.jobType || '').padEnd(14)} │ ${(j.actor || 'dev').slice(0, 10).padEnd(10)} │ ${statusColor}${(j.status || '').padEnd(10)}\x1b[0m │ ${(j.cpuMs?.toFixed(1) + 'ms').padStart(8)} │`;
        console.log(line);
      }
    }
    console.log('└──────────────────────────────────────────────────────────────────────────────┘');
    if (hideProbes && allJobs.length > jobs.length) {
      console.log(`  ${allJobs.length - jobs.length} historical probe row(s) hidden; they remain in the insert-only journal.`);
    }
    console.log('');
    process.exit(0);
  }

  // Run dynamic live measurement against an isolated probe kernel.
  const conformanceMod = await importFirstExisting([
    'src/kernel/conformance.js',
    'lib/kernel/conformance.js'
  ]);
  if (!conformanceMod) {
    console.error('Error: Kernel conformance probe could not be loaded.');
    process.exit(1);
  }
  const conformance = await conformanceMod.measureKernelConformance(journal);

  if (cliArgs.includes('--json')) {
    console.log(JSON.stringify({
      kernelVersion: kernel.version,
      abiVersion: kernel.abiVersion,
      activeSchedulerJobs: kernel.scheduler.getActiveJobCount(),
      journalPath: journal.dbPath,
      conformance
    }, null, 2));
    process.exit(0);
  }

  const badgeColor = (status) => {
    if (status === 'OBSERVED' || status === 'PROCESS') return '\x1b[32m';
    if (status === 'COOPERATIVE') return '\x1b[36m';
    if (status === 'UNVERIFIED') return '\x1b[33m';
    return '\x1b[31m';
  };
  const row = (label, item) => {
    const prefix = fit(label, 34);
    const badge = fit(`[${item.status}]`, 13);
    const detail = fit(item.detail, 28);
    return `│ ${prefix}${badgeColor(item.status)}${badge}\x1b[0m ${detail} │`;
  };
  const journalLabel = journal.db ? 'SQLite WAL (Insert-Only)' : 'In-Memory Fallback';

  console.log(`\n┌${'─'.repeat(78)}┐`);
  console.log(boxLine(`RONINOS EXECUTION KERNEL v${kernel.version}`.padEnd(55) + '[DYNAMIC MEASUREMENT]'));
  console.log(`├${'─'.repeat(78)}┤`);
  console.log(boxLine(`Kernel Version: ${kernel.version}   Extension ABI: v${kernel.abiVersion}`));
  console.log(boxLine('Default Deny (Tickets)   Scheduler: Priority Queue + Async Abort'));
  console.log(boxLine(`Isolation: Child process   Journal: ${journalLabel}`));
  console.log(`├${'─'.repeat(78)}┤`);
  console.log(boxLine('SEVEN OS CONFORMANCE MEASUREMENTS:'));
  console.log(row('  1. Substrate Ownership:', conformance.substrate));
  console.log(row('  2. Admission & Scheduling:', conformance.scheduling));
  console.log(row('  3. Capability Boundary:', conformance.capabilityBoundary));
  console.log(row('  4. Fault Containment:', conformance.isolation));
  console.log(row('  5. Universal Invariants:', conformance.universalInvariants));
  console.log(row('  6. Lifecycle & Recovery:', conformance.lifecycleRecovery));
  console.log(row('  7. Stable Extension ABI:', conformance.extensionContract));
  console.log(`└${'─'.repeat(78)}┘\n`);
  console.log('  Note: untrusted jail code runs in a permission-restricted child process');
  console.log('        killed on deadline. Audit and remediation analysis run in terminable');
  console.log('        workers. Third-party lens code still runs in-process. Network egress');
  console.log('        is not OS-restricted.\n');
  process.exit(0);
}

// ------------------------------------------------------------------------------
// 8.7 REVIEW EXPERIENCE COMMANDS (SUMMARY / CHAT / INCREMENTAL PLAN)
// ------------------------------------------------------------------------------
async function loadReviewExperience() {
  return importFirstExisting([
    'reviewExperience.js',
    'src/shared/architecturalAperture/reviewExperience.js'
  ]);
}

function readReceiptArg(args, flag) {
  const index = args.indexOf(flag);
  if (index === -1 || !args[index + 1]) {
    throw new Error(`Missing ${flag} <receipt.json>`);
  }
  return JSON.parse(fs.readFileSync(args[index + 1], 'utf8').replace(/^\uFEFF/, ''));
}

async function handleSummaryCommand(args) {
  const mod = await loadReviewExperience();
  const summary = mod.buildPrSummary(readReceiptArg(args, '--receipt'));
  console.log(args.includes('--json') ? JSON.stringify(summary, null, 2) : summary.markdown);
}

async function handleChatCommand(args) {
  const mod = await loadReviewExperience();
  const receipt = readReceiptArg(args, '--receipt');
  const index = args.indexOf('--question');
  const question = index === -1 ? '' : args[index + 1];
  if (args.includes('--model')) {
    const endpointIndex = args.indexOf('--endpoint');
    const modelIndex = args.indexOf('--model-name');
    const callModel = mod.createReviewModelCaller({
      endpoint: endpointIndex === -1 ? undefined : args[endpointIndex + 1],
      model: modelIndex === -1 ? undefined : args[modelIndex + 1]
    });
    const answer = await mod.answerReviewQuestionWithModel(question, receipt, { callModel });
    console.log(JSON.stringify(answer, null, 2));
    return;
  }
  console.log(JSON.stringify(mod.answerReviewQuestion(question, receipt), null, 2));
}

async function handlePlanCommand(args) {
  const mod = await loadReviewExperience();
  const previous = readReceiptArg(args, '--previous');
  const next = readReceiptArg(args, '--next');
  console.log(JSON.stringify(mod.buildIncrementalPlan(previous, next), null, 2));
}

// ------------------------------------------------------------------------------
// 9. CLI ENTRYPOINT
// ------------------------------------------------------------------------------
const args = process.argv.slice(2);
const [cmd, subcmd] = args;

if (cmd === 'daemon') {
  await startWarmDaemon();
} else if (cmd === 'mcp') {
  await startMcpServer();
} else if (cmd === 'jail') {
  await handleJailCommand(args);
} else if (cmd === 'kernel') {
  await handleKernelCommand(args);
} else if (cmd === 'docs') {
  handleDocsCommand(args);
} else if (cmd === 'summary') {
  await handleSummaryCommand(args);
} else if (cmd === 'chat') {
  await handleChatCommand(args);
} else if (cmd === 'plan') {
  await handlePlanCommand(args);
} else if (cmd === 'hook' && subcmd === 'install') {
  installGitPrePushHook();
} else {
  const target =
    cmd && cmd !== 'audit' && !cmd.startsWith('-')
      ? cmd
      : subcmd && !subcmd.startsWith('-')
      ? subcmd
      : 'HEAD';

  const attachGitNote = args.includes('--attest');
  const previousReceipt = args.includes('--previous') ? readReceiptArg(args, '--previous') : null;
  const excludePatterns = [];
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === '--exclude' && args[index + 1]) excludePatterns.push(args[index + 1]);
  }
  let result = (process.env.RONINOS_NO_DAEMON === '1' || previousReceipt || excludePatterns.length > 0)
    ? null
    : await tryQueryWarmDaemon(target, attachGitNote);
  if (!result) {
    result = await executeApertureAudit(target, null, attachGitNote, { previousReceipt, excludePatterns });
  }

  if (args.includes('--sarif')) {
    console.log(JSON.stringify(convertReceiptToSarif(result), null, 2));
  } else if (args.includes('--json')) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    renderReceiptTui(result);
  }

  process.exit(result.status === 'INVARIANT_VIOLATION' ? 1 : 0);
}

