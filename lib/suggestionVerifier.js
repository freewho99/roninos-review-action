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

  return {
    verified: true,
    reason: 'TREE_SITTER_CLEAN_PARSE',
    suggestion: applied.added.join('\n'),
    startLine: applied.oldStart,
    endLine: applied.oldStart + applied.oldCount - 1,
  };
}
