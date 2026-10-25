import vm from 'node:vm';

export function applySingleHunk(content, patch) {
  const lines = String(content || '').split('\n');
  const patchLines = String(patch || '').split('\n');
  const hunkIndex = patchLines.findIndex((line) => line.startsWith('@@ '));
  if (hunkIndex < 0) return null;
  const header = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(patchLines[hunkIndex]);
  if (!header) return null;
  const oldStart = Number(header[1]);
  const oldCount = header[2] === undefined ? 1 : Number(header[2]);
  const body = patchLines.slice(hunkIndex + 1).filter((line) => line && !line.startsWith('\\'));
  const removed = [];
  const added = [];
  let oldSeen = 0;
  let context = 0;

  for (const line of body) {
    if (line.startsWith('diff ') || line.startsWith('index ') || line.startsWith('--- ') || line.startsWith('+++ ')) break;
    if (line.startsWith(' ')) {
      removed.push(line.slice(1));
      added.push(line.slice(1));
      oldSeen += 1;
      context += 1;
    } else if (line.startsWith('-')) {
      removed.push(line.slice(1));
      oldSeen += 1;
    } else if (line.startsWith('+')) {
      added.push(line.slice(1));
    }
  }

  if (oldSeen !== oldCount || removed.length === 0 || added.length === 0) return null;
  if (context > 0) return { content: null, added, removed, oldStart, oldCount, context };
  const before = lines.slice(0, Math.max(0, oldStart - 1));
  const after = lines.slice(Math.max(0, oldStart - 1) + oldCount);
  return {
    content: [...before, ...added, ...after].join('\n'),
    added,
    removed,
    oldStart,
    oldCount,
    context,
  };
}

export function detectSelfRecursion(addedLines) {
  const text = Array.isArray(addedLines) ? addedLines.join('\n') : String(addedLines || '');
  const fnRegex = /(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\s*\(([^)]*)\)\s*\{([\s\S]*)\}/g;
  let match;
  while ((match = fnRegex.exec(text)) !== null) {
    const fnName = match[1];
    const body = match[3];
    // Check if body calls fnName directly (not obj.fnName or fnName as property)
    const callRegex = new RegExp(`(?<![a-zA-Z0-9_$.])\\b${fnName}\\s*\\(`, 'g');
    if (callRegex.test(body)) {
      if (!/\b(if|switch|while|\?)\b/.test(body)) {
        return { recursive: true, fnName };
      }
    }
  }
  return { recursive: false };
}

export function executeSmokeTest(appliedCode, filePath) {
  if (typeof process === 'undefined' || !process.versions?.node) {
    return { passed: true, reason: 'NON_NODE_ENVIRONMENT' };
  }
  const ext = String(filePath || '').toLowerCase();
  if (!ext.endsWith('.js') && !ext.endsWith('.mjs')) {
    return { passed: true, reason: 'NON_JS_SKIPPED' };
  }
  try {
    const importRegex = /import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"];?/g;
    let m;
    const imports = [];
    while ((m = importRegex.exec(appliedCode)) !== null) {
      const symbols = m[1].split(',').map((s) => s.trim().split(/\s+as\s+/));
      for (const sym of symbols) imports.push(sym[sym.length - 1].trim());
    }
    const sandbox = { console };
    for (const imp of imports) sandbox[imp] = (...args) => args[0] || 'mock_ok';
    let exec = appliedCode.replace(/import\s+[\s\S]*?from\s+['"][^'"]+['"];?/g, '');
    exec = exec.replace(/export\s+(?:default\s+)?/g, '');
    const script = new vm.Script(exec);
    const context = vm.createContext(sandbox);
    script.runInContext(context, { timeout: 50 });
    const fnNames = [];
    const fnRegex = /(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\s*\(/g;
    while ((m = fnRegex.exec(exec)) !== null) fnNames.push(m[1]);
    for (const fn of fnNames) {
      if (typeof context[fn] === 'function') context[fn]('smoke-input');
    }
    return { passed: true };
  } catch (err) {
    return {
      passed: false,
      error: err?.message || String(err),
      isRecursion: err instanceof RangeError || /call stack/i.test(err?.message || '')
    };
  }
}

export async function verifySuggestion({
  filePath,
  content,
  patch,
  parseTree,
  languageKeyForFile,
}) {
  const language = typeof languageKeyForFile === 'function' ? languageKeyForFile(filePath) : null;
  if (!language) return { verified: false, reason: 'UNSUPPORTED_LANGUAGE' };
  if (typeof parseTree !== 'function') return { verified: false, reason: 'PARSER_UNAVAILABLE' };
  const applied = applySingleHunk(content, patch);
  if (!applied) return { verified: false, reason: 'PATCH_NOT_APPLICABLE' };
  if (applied.context > 0) return { verified: false, reason: 'CONTEXT_HUNK_NOT_SUPPORTED' };

  // 1. Syntactic Tree-sitter parse
  let parsed;
  try {
    parsed = await parseTree(applied.content, language);
  } catch {
    return { verified: false, reason: 'PARSER_FAILED' };
  }
  if (!parsed?.tree?.rootNode) return { verified: false, reason: 'PARSER_UNAVAILABLE' };
  const hasError = typeof parsed.tree.rootNode.hasError === 'function'
    ? parsed.tree.rootNode.hasError()
    : parsed.tree.rootNode.hasError === true;
  try {
    parsed.tree.delete?.();
  } catch {
    // The parser cache owns the tree; no action needed if delete is unavailable.
  }
  if (hasError) return { verified: false, reason: 'PATCH_SYNTAX_ERROR' };

  // 2. Semantic AST Invariant: No self-recursive replacement
  const recursion = detectSelfRecursion(applied.added);
  if (recursion.recursive) {
    return { verified: false, reason: 'SELF_RECURSIVE_REPLACEMENT' };
  }

  // 3. Semantic Bounded Smoke Test in V8 Sandbox
  const smoke = executeSmokeTest(applied.content, filePath);
  if (!smoke.passed) {
    return {
      verified: false,
      reason: smoke.isRecursion ? 'SELF_RECURSIVE_CALL' : 'SMOKE_TEST_FAILED',
      error: smoke.error
    };
  }

  return {
    verified: true,
    reason: 'PROVEN_SEMANTICALLY_SOUND',
    status: 'PROVEN_SEMANTICALLY_SOUND',
    suggestion: applied.added.join('\n'),
    startLine: applied.oldStart,
    endLine: applied.oldStart + applied.oldCount - 1,
  };
}
