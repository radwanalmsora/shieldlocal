'use strict';
const { SEVERITIES, summarize } = require('./scanner');

const ICON = { critical: '🟥', high: '🟧', medium: '🟨', low: '🟦', info: '⬜' };

/** Markdown report. items = [{file, findings}] */
function buildMarkdown(items, meta = {}) {
  const all = items.flatMap((i) => i.findings);
  const s = summarize(all);
  const out = [];
  out.push('# ShieldLocal Security Report', '');
  out.push(`Generated: ${meta.date || new Date().toISOString()}  `);
  out.push(`Files with findings: **${items.filter((i) => i.findings.length).length}**  `);
  out.push(`Security score: **${s.score}/100 (grade ${s.grade})**`, '');
  out.push('| Severity | Count |', '|---|---:|');
  for (const sev of SEVERITIES) out.push(`| ${ICON[sev]} ${sev} | ${s.bySeverity[sev]} |`);
  out.push('');
  for (const sev of SEVERITIES) {
    const rows = [];
    for (const { file, findings } of items) for (const f of findings) if (f.severity === sev) rows.push({ file, f });
    if (!rows.length) continue;
    out.push(`## ${ICON[sev]} ${sev[0].toUpperCase() + sev.slice(1)} (${rows.length})`, '');
    for (const { file, f } of rows) {
      out.push(`### ${f.title}`);
      out.push(`- **Location:** \`${file}:${f.line + 1}\``);
      if (f.cwe) out.push(`- **CWE:** [CWE-${f.cwe}](https://cwe.mitre.org/data/definitions/${f.cwe}.html)`);
      out.push(`- **Issue:** ${f.message}`);
      out.push(`- **Fix:** ${f.remediation}`);
      out.push('```', f.snippet, '```', '');
    }
  }
  if (!all.length) out.push('✅ No findings.', '');
  out.push('---', '_Scanned locally by ShieldLocal. No code left this machine._');
  return out.join('\n');
}

module.exports = { buildMarkdown };
