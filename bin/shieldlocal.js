#!/usr/bin/env node
'use strict';
/* ShieldLocal CLI – same engine as the VS Code extension. Offline, zero dependencies. */
const fs = require('fs');
const path = require('path');
const { scanText, summarize, langFromFile, SEVERITY_RANK, SCANNABLE_EXTENSIONS } = require('../src/scanner');
const { scanDependencies, isDependencyFile } = require('../src/deps');
const { buildSarif } = require('../src/sarif');
const { buildMarkdown } = require('../src/report');
const pkg = require('../package.json');

const args = process.argv.slice(2);
const opt = { format: 'text', failOn: 'none', min: 'low', out: null, target: '.' };
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--format' || a === '-f') opt.format = args[++i];
  else if (a === '--fail-on') opt.failOn = args[++i];
  else if (a === '--min-severity') opt.min = args[++i];
  else if (a === '--out' || a === '-o') opt.out = args[++i];
  else if (a === '--help' || a === '-h') { help(); process.exit(0); }
  else if (a === '--version' || a === '-v') { console.log(pkg.version); process.exit(0); }
  else opt.target = a;
}
function help() {
  console.log(`ShieldLocal ${pkg.version} – offline security scanner

Usage: shieldlocal [path] [options]

  -f, --format <text|json|sarif|md>   output format (default: text)
  -o, --out <file>                    write output to a file
      --min-severity <level>          critical|high|medium|low|info (default: low)
      --fail-on <level>               exit 1 if a finding >= level exists (CI gate)
  -h, --help   -v, --version`);
}

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', '.venv', 'venv', 'vendor', '__pycache__', 'coverage', '.next', 'target']);
const MAX = 1024 * 1024;
const root = path.resolve(opt.target);
const files = [];
(function walk(p) {
  let st;
  try { st = fs.statSync(p); } catch { return; }
  if (st.isDirectory()) {
    if (SKIP_DIRS.has(path.basename(p)) && p !== root) return;
    for (const n of fs.readdirSync(p)) walk(path.join(p, n));
  } else if (st.size <= MAX) {
    const b = path.basename(p);
    if (/\.min\.js$|\.map$|\.lock$/.test(b)) return;
    if (langFromFile(p) || isDependencyFile(p)) files.push(p);
  }
})(root);

const items = [];
for (const f of files) {
  const text = fs.readFileSync(f, 'utf8');
  if (text.includes('\u0000')) continue;
  const rel = path.relative(root, f) || path.basename(f);
  let findings = isDependencyFile(f)
    ? scanDependencies(text, f)
    : scanText(text, { lang: langFromFile(f), file: f, minSeverity: opt.min });
  findings = findings.filter((x) => SEVERITY_RANK[x.severity] >= SEVERITY_RANK[opt.min]);
  if (findings.length) items.push({ file: rel, findings });
}
const all = items.flatMap((i) => i.findings);

let output;
if (opt.format === 'sarif') output = JSON.stringify(buildSarif(items, pkg.version), null, 2);
else if (opt.format === 'json') output = JSON.stringify({ summary: summarize(all), files: items }, null, 2);
else if (opt.format === 'md') output = buildMarkdown(items);
else {
  const c = { critical: '\x1b[1;31m', high: '\x1b[31m', medium: '\x1b[33m', low: '\x1b[34m', info: '\x1b[90m' };
  const lines = [];
  for (const { file, findings } of items) {
    lines.push(`\n\x1b[4m${file}\x1b[0m`);
    for (const f of findings) lines.push(`  ${String(f.line + 1).padStart(4)}:${String(f.col + 1).padEnd(3)} ${c[f.severity]}${f.severity.padEnd(8)}\x1b[0m ${f.title}  \x1b[90m${f.ruleId}\x1b[0m`);
  }
  const s = summarize(all);
  lines.push(`\n${all.length ? '✖' : '✔'} ${all.length} finding(s) in ${items.length} file(s) · ${files.length} scanned · score ${s.score}/100 (${s.grade})`);
  output = lines.join('\n');
}
if (opt.out) fs.writeFileSync(opt.out, output); else console.log(output);

if (opt.failOn !== 'none' && all.some((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK[opt.failOn])) process.exit(1);
