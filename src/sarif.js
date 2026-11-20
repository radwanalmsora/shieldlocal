'use strict';
const { RULES } = require('./rules');

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SCORE = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '1.0' };

/** Build a SARIF 2.1.0 log (GitHub Code Scanning compatible). items = [{file, findings}] */
function buildSarif(items, version = '1.0.0') {
  const used = new Map();
  const results = [];
  for (const { file, findings } of items) {
    for (const f of findings) {
      used.set(f.ruleId, f);
      results.push({
        ruleId: f.ruleId,
        level: LEVEL[f.severity],
        message: { text: `${f.message} ${f.remediation}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: file.replace(/\\/g, '/'), uriBaseId: '%SRCROOT%' },
            region: { startLine: f.line + 1, startColumn: f.col + 1, endColumn: f.endCol + 1, snippet: { text: f.snippet } },
          },
        }],
      });
    }
  }
  const ruleIndex = new Map(RULES.map((r) => [r.id, r]));
  const rules = [...used.entries()].map(([id, f]) => {
    const r = ruleIndex.get(id);
    return {
      id,
      name: f.title.replace(/[^A-Za-z0-9]+/g, ''),
      shortDescription: { text: f.title },
      fullDescription: { text: f.message },
      help: { text: f.remediation, markdown: `**${f.title}**\n\n${f.message}\n\n**Fix:** ${f.remediation}` },
      defaultConfiguration: { level: LEVEL[f.severity] },
      properties: {
        'security-severity': SCORE[f.severity],
        tags: ['security', f.category, ...(r && r.cwe ? [`external/cwe/cwe-${r.cwe}`] : [])],
      },
    };
  });
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'ShieldLocal', version, informationUri: 'https://github.com/radwanalmsora/shieldlocal', rules } },
      results,
    }],
  };
}

module.exports = { buildSarif };
