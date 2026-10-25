#!/usr/bin/env node
import fs from 'node:fs';

function globToRegExp(pattern) {
  const escaped = String(pattern)
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '.')
    .replace(/\u0000\//g, '(?:.*/)?')
    .replace(/\u0000/g, '.*');
  return new RegExp(`^${escaped}$`);
}

export function filterReceipt(receipt, patterns = []) {
  const regexes = patterns.filter(Boolean).map(globToRegExp);
  if (regexes.length === 0) return receipt;
  const checks = (receipt.checks || []).filter(
    (check) => !check.file || !regexes.some((regex) => regex.test(check.file)),
  );
  const failed = checks.some((check) => check.status === 'FAILED' || check.status === 'VIOLATION');
  return {
    ...receipt,
    checks,
    status: failed ? 'INVARIANT_VIOLATION' : 'DETERMINISTIC_PASS',
    totalFailed: checks.filter((check) => check.status === 'FAILED').length,
  };
}

function main(argv) {
  const [file, pattern] = argv;
  if (!file || !pattern) {
    console.error('Usage: node filter-receipt.mjs <receipt.json> <glob>');
    process.exitCode = 1;
    return;
  }
  const receipt = JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
  fs.writeFileSync(file, JSON.stringify(filterReceipt(receipt, [pattern]), null, 2));
}

if (process.argv[1] && process.argv[1].endsWith('filter-receipt.mjs')) {
  main(process.argv.slice(2));
}
