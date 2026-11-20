'use strict';
const path = require('path');
const { RULES, getRule } = require('./rules');

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const EXT_LANG = {
  js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascriptreact',
  ts: 'typescript', mts: 'typescript', cts: 'typescript', tsx: 'typescriptreact',
  vue: 'vue', svelte: 'svelte', html: 'html', htm: 'html',
  py: 'python', php: 'php', java: 'java', go: 'go', cs: 'csharp', rb: 'ruby',
  sh: 'shellscript', bash: 'shellscript', zsh: 'shellscript',
  yml: 'yaml', yaml: 'yaml', json: 'json', properties: 'properties', ini: 'ini',
  toml: 'toml', env: 'dotenv', conf: 'plaintext', cfg: 'ini',
};
const SCANNABLE_EXTENSIONS = Object.keys(EXT_LANG);

/** Resolve a language id from a file name (used by the CLI and for .env detection). */
function langFromFile(file) {
  const base = path.basename(file || '');
  if (/^\.env(\..+)?$/i.test(base) || /\.env$/i.test(base)) return 'dotenv';
  if (/^dockerfile(\..+)?$/i.test(base) || /\.dockerfile$/i.test(base)) return 'dockerfile';
  const ext = base.includes('.') ? base.split('.').pop().toLowerCase() : '';
  return EXT_LANG[ext] || null;
}

const COMMENT_START = /^\s*(?:\/\/|#|\*|\/\*|--|<!--|;)/;
const IGNORE_RE = /shieldlocal-ignore(?!-file)(?:\s*:\s*([\w\-, ]+))?/i;

function redact(text, start, end) {
  const secret = text.slice(start, end);
  const keep = secret.length > 10 ? secret.slice(0, 4) : secret.slice(0, 1);
  return text.slice(0, start) + keep + '••••••' + text.slice(end);
}

function isIgnored(lines, idx, ruleId) {
  const test = (s) => {
    const m = IGNORE_RE.exec(s);
    if (!m) return false;
    if (!m[1]) return true;
    return m[1].split(/[,\s]+/).filter(Boolean).includes(ruleId);
  };
  if (test(lines[idx])) return true;
  if (idx > 0 && COMMENT_START.test(lines[idx - 1]) && test(lines[idx - 1])) return true;
  return false;
}

/**
 * Scan source text. Pure function – no I/O – so it runs in the extension host, the CLI and tests.
 * @returns {Array} findings
 */
function scanText(text, opts = {}) {
  const lang = opts.lang || langFromFile(opts.file) || 'plaintext';
  const disabled = new Set(opts.disabledRules || []);
  const minRank = SEVERITY_RANK[opts.minSeverity || 'info'] ?? 0;
  const maxLineLength = opts.maxLineLength || 2000;

  if (/shieldlocal-ignore-file/i.test(text.slice(0, 600))) return [];

  const lines = text.split(/\r?\n/);
  const rules = RULES.filter(
    (r) => !disabled.has(r.id) && SEVERITY_RANK[r.severity] >= minRank && (!r.langs || r.langs.includes(lang))
  );
  const findings = [];
  const seen = new Set();

  for (let i = 0; i < lines.length; i++) {
    const lineText = lines[i];
    if (!lineText || lineText.length > maxLineLength) continue;
    const isComment = COMMENT_START.test(lineText);

    for (const rule of rules) {
      if (isComment && rule.category !== 'secrets') continue;
      const re = rule.pattern;
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(lineText)) !== null) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        const ctx = { m, lineText, text, lang, file: opts.file };
        if (rule.filter && !rule.filter(ctx)) continue;
        if (isIgnored(lines, i, rule.id)) continue;

        // multiline-anchored rules may start on leading whitespace – trim for a tight squiggle
        const lead = m[0].length - m[0].trimStart().length;
        const col = m.index + lead;
        const endCol = m.index + m[0].trimEnd().length;
        const key = `${rule.id}:${i}:${col}`;
        if (seen.has(key)) continue;
        seen.add(key);

        let fix = null;
        if (rule.fix && (!rule.fix.when || rule.fix.when(ctx))) {
          const original = m[0];
          const replacement = rule.fix.apply(m, ctx);
          // apply() returns a replacement for the *untrimmed* match
          if (replacement !== original) {
            fix = { title: rule.fix.title, newText: replacement.trim(), col, endCol };
          }
        }

        const snippetRaw = lineText.trim();
        const off = lineText.indexOf(snippetRaw);
        const snippet = (rule.category === 'secrets'
          ? redact(snippetRaw, Math.max(0, col - off), Math.max(0, endCol - off))
          : snippetRaw
        ).slice(0, 180);

        findings.push({
          ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category,
          cwe: rule.cwe, message: rule.message, remediation: rule.remediation,
          line: i, col, endCol, snippet, fix,
        });
      }
    }
  }
  findings.sort((a, b) => a.line - b.line || a.col - b.col);
  return findings;
}

const WEIGHT = { critical: 25, high: 10, medium: 4, low: 1, info: 0 };

function summarize(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byCategory = {};
  for (const f of findings) {
    bySeverity[f.severity]++;
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
  }
  let penalty = 0;
  for (const s of SEVERITIES) penalty += Math.min(bySeverity[s] * WEIGHT[s], s === 'critical' ? 75 : 40);
  const score = Math.max(0, 100 - penalty);
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 65 ? 'C' : score >= 45 ? 'D' : 'F';
  return { total: findings.length, bySeverity, byCategory, score, grade };
}

module.exports = {
  scanText, summarize, langFromFile, getRule,
  SEVERITIES, SEVERITY_RANK, SCANNABLE_EXTENSIONS, EXT_LANG,
};
