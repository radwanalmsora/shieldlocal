'use strict';
const path = require('path');
const fs = require('fs');

let BUNDLED = null;
function bundled() {
  if (!BUNDLED) BUNDLED = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'advisories.json'), 'utf8')).advisories;
  return BUNDLED;
}

function parseVersion(v) {
  const m = /(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(String(v || ''));
  return m ? [+m[1], +(m[2] || 0), +(m[3] || 0)] : null;
}
function cmp(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}
function isVulnerable(version, ranges) {
  const v = parseVersion(version);
  if (!v) return false;
  return ranges.some((r) => {
    const lo = r.introduced ? parseVersion(r.introduced) : [0, 0, 0];
    const hi = r.fixed ? parseVersion(r.fixed) : null;
    return cmp(v, lo) >= 0 && (!hi || cmp(v, hi) < 0);
  });
}

const DOWN = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };

function isDependencyFile(file) {
  const b = path.basename(file || '').toLowerCase();
  return b === 'package.json' || b === 'package-lock.json' || /^requirements.*\.txt$/.test(b);
}

function lineOf(lines, needle) {
  const i = lines.findIndex((l) => l.includes(needle));
  return i < 0 ? 0 : i;
}

function toFinding(adv, lines, needle, name, version, exact, extraNote) {
  const line = lineOf(lines, needle);
  const col = Math.max(0, lines[line].indexOf(name) - 1);
  const sev = exact ? adv.severity : DOWN[adv.severity];
  const fixed = adv.ranges[adv.ranges.length - 1].fixed;
  return {
    ruleId: 'dep-' + adv.id.toLowerCase(),
    title: `${name}@${version} – ${adv.id}`,
    severity: sev, category: 'dependencies', cwe: null, advisory: adv.id,
    message: `${adv.summary}.${extraNote || ''}`,
    remediation: fixed ? `Upgrade ${name} to ${fixed} or later.` : `Replace or patch ${name}.`,
    line, col: Math.max(col, 0), endCol: Math.max(col, 0) + name.length + 2,
    snippet: lines[line].trim().slice(0, 180), fix: null,
  };
}

/**
 * Check a dependency manifest against the bundled (and optional custom) advisories.
 * Supports package.json, package-lock.json and requirements*.txt.
 */
function scanDependencies(text, file, extra = []) {
  const base = path.basename(file || '').toLowerCase();
  const advisories = bundled().concat(extra || []);
  const lines = text.split(/\r?\n/);
  const out = [];
  const find = (eco, name) => advisories.filter((a) => a.eco === eco && a.name.toLowerCase() === name.toLowerCase());

  try {
    if (base === 'package.json') {
      const pkg = JSON.parse(text);
      const all = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}), ...(pkg.optionalDependencies || {}) };
      for (const [name, spec] of Object.entries(all)) {
        const exact = /^\d/.test(spec);
        for (const adv of find('npm', name)) {
          if (isVulnerable(spec, adv.ranges)) {
            out.push(toFinding(adv, lines, `"${name}"`, name, spec, exact,
              exact ? '' : ' The declared range allows a vulnerable version – check your lockfile.'));
          }
        }
      }
    } else if (base === 'package-lock.json') {
      const lock = JSON.parse(text);
      const pk = lock.packages || {};
      for (const [key, info] of Object.entries(pk)) {
        if (!key || !info.version) continue;
        const name = key.split('node_modules/').pop();
        for (const adv of find('npm', name)) {
          if (isVulnerable(info.version, adv.ranges)) {
            out.push(toFinding(adv, lines, `"${key}"`, name, info.version, true, info.dev ? ' (dev dependency)' : ''));
          }
        }
      }
    } else if (/^requirements.*\.txt$/.test(base)) {
      lines.forEach((raw, i) => {
        const m = /^\s*([A-Za-z0-9_.-]+)\s*(==|~=|>=)\s*([\d.]+)/.exec(raw);
        if (!m) return;
        const exact = m[2] === '==';
        for (const adv of find('pypi', m[1])) {
          if (isVulnerable(m[3], adv.ranges)) {
            const f = toFinding(adv, lines, raw, m[1], m[3], exact,
              exact ? '' : ' The specifier allows a vulnerable version.');
            f.line = i; f.col = 0; f.endCol = raw.length;
            out.push(f);
          }
        }
      });
    }
  } catch (_) { /* malformed manifest – nothing to report */ }
  return out;
}

module.exports = { scanDependencies, isDependencyFile, isVulnerable, parseVersion };
