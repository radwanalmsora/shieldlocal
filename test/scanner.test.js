'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { scanText, summarize, langFromFile } = require('../src/scanner');
const { scanDependencies, isVulnerable } = require('../src/deps');
const { buildSarif } = require('../src/sarif');
const { RULES } = require('../src/rules');

// Secret-shaped fixtures are assembled at runtime so GitHub push-protection never sees a literal token.
const AWS = 'AKIA' + 'QWERTYUIOPASDFGH';
const GH = 'ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8';
const STRIPE = 'sk_' + 'live_' + '4eC39HqLyjWDarjtT1zdp7dc';

const ids = (src, lang, opts = {}) => scanText(src, { lang, ...opts }).map((f) => f.ruleId);

test('rule catalogue is sane', () => {
  const seen = new Set();
  for (const r of RULES) {
    assert.ok(!seen.has(r.id), `duplicate id ${r.id}`);
    seen.add(r.id);
    assert.ok(r.pattern.global, `${r.id} must be global`);
    assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(r.severity));
    assert.ok(r.message && r.remediation);
  }
  assert.ok(RULES.length >= 70);
});

test('detects secrets and redacts them in the snippet', () => {
  const f = scanText(`const k = "${AWS}";\nconst t = "${GH}";\nconst s = "${STRIPE}";`, { lang: 'javascript' });
  assert.deepStrictEqual(f.map((x) => x.ruleId).sort(), ['secret-aws-access-key', 'secret-github-token', 'secret-stripe-key']);
  for (const x of f) {
    assert.ok(!x.snippet.includes(AWS.slice(8)) && !x.snippet.includes(GH.slice(10)), 'snippet must be redacted');
    assert.strictEqual(x.severity, 'critical');
  }
});

test('hard-coded credentials, with env-var quick fix', () => {
  const [f] = scanText('const password = "Sup3rS3cret!";', { lang: 'javascript' });
  assert.strictEqual(f.ruleId, 'secret-hardcoded-credential');
  assert.strictEqual(f.fix.newText, 'password = process.env.PASSWORD');
  const [p] = scanText('DB_PASSWORD = "hunter2hunter2"', { lang: 'python' });
  assert.strictEqual(p.fix.newText, 'DB_PASSWORD = os.environ["DB_PASSWORD"]');
});

test('does not flag placeholders or env lookups', () => {
  const src = [
    'const token = "Bearer";', 'cfg.password = "changeme";', 'const secret = process.env.SECRET;',
    'const apiKey = "<your-api-key>";', 'const label = "Enter your password";', 'password = "${DB_PASS}"',
  ].join('\n');
  assert.deepStrictEqual(ids(src, 'javascript'), []);
});

test('.env files', () => {
  assert.deepStrictEqual(ids('DB_PASSWORD=hunter2hunter2\nAPI_KEY=your_api_key_here\nSECRET_TOKEN=${X}', 'dotenv'), ['secret-env-assignment']);
  assert.strictEqual(langFromFile('/a/b/.env.production'), 'dotenv');
  assert.strictEqual(langFromFile('Dockerfile'), 'dockerfile');
});

test('SQL injection variants', () => {
  assert.deepStrictEqual(ids('db.query("SELECT * FROM u WHERE id = " + req.query.id);', 'javascript'), ['sql-concat']);
  assert.deepStrictEqual(ids('db.query(`SELECT * FROM t WHERE a = ${id}`);', 'javascript'), ['sql-template']);
  assert.deepStrictEqual(ids('cur.execute(f"SELECT * FROM t WHERE id={uid}")', 'python'), ['sql-fstring']);
  assert.deepStrictEqual(ids('cur.execute("SELECT * FROM t WHERE id=%s" % uid)', 'python'), ['sql-concat']);
  assert.deepStrictEqual(ids(`cur.execute(f"SELECT * FROM users WHERE name = '{request.args['n']}'")`, 'python'), ['sql-fstring']);
  assert.deepStrictEqual(ids('cur.execute("SELECT * FROM t WHERE id=%s", (uid,))', 'python'), []);
  assert.deepStrictEqual(ids('db.query("SELECT * FROM t WHERE id = $1", [id]);', 'javascript'), []);
});

test('command injection and eval', () => {
  assert.deepStrictEqual(ids('const cp=require("child_process"); cp.exec("ls " + dir);', 'javascript'), ['cmd-node-exec']);
  assert.deepStrictEqual(ids('const m = re.exec(str);', 'javascript'), [], 'RegExp.exec must not match');
  assert.deepStrictEqual(ids('eval(code)', 'javascript'), ['code-eval']);
  assert.deepStrictEqual(ids('subprocess.run(cmd, shell=True)', 'python'), ['cmd-python-shell']);
});

test('XSS rules ignore static strings', () => {
  assert.deepStrictEqual(ids('el.innerHTML = userInput;', 'javascript'), ['xss-innerhtml']);
  assert.deepStrictEqual(ids('el.innerHTML = "<b>hi</b>";', 'javascript'), []);
  assert.deepStrictEqual(ids('<div dangerouslySetInnerHTML={{__html: x}} />', 'javascriptreact'), ['xss-react-dangerous']);
});

test('quick fixes produce safe replacements', () => {
  const fix = (src, lang) => scanText(src, { lang })[0].fix.newText;
  assert.strictEqual(fix('crypto.createHash("md5")', 'javascript'), 'createHash("sha256")');
  assert.strictEqual(fix('hashlib.md5(x)', 'python'), 'hashlib.sha256(');
  assert.strictEqual(fix('requests.get(u, verify=False)', 'python'), 'verify=True');
  assert.strictEqual(fix('yaml.load(s)', 'python'), 'yaml.safe_load(');
  assert.strictEqual(scanText('yaml.load(s, Loader=yaml.Loader)', { lang: 'python' })[0].fix, null);
});

test('ignore comments and ignore-file', () => {
  assert.deepStrictEqual(ids('eval(x); // shieldlocal-ignore', 'javascript'), []);
  assert.deepStrictEqual(ids('eval(x); // shieldlocal-ignore: code-eval', 'javascript'), []);
  assert.deepStrictEqual(ids('eval(x); // shieldlocal-ignore: other-rule', 'javascript'), ['code-eval']);
  assert.deepStrictEqual(ids('// shieldlocal-ignore\neval(x);', 'javascript'), []);
  assert.deepStrictEqual(ids('// shieldlocal-ignore-file\neval(x);', 'javascript'), []);
});

test('commented-out code is skipped (but secrets in comments are not)', () => {
  assert.deepStrictEqual(ids('// eval(x)', 'javascript'), []);
  assert.deepStrictEqual(ids(`// key = ${AWS}`, 'javascript'), ['secret-aws-access-key']);
});

test('options: disabled rules, minimum severity, language scoping', () => {
  assert.deepStrictEqual(ids('eval(x)', 'javascript', { disabledRules: ['code-eval'] }), []);
  assert.deepStrictEqual(ids('fetch("http://api.evil.com/x")', 'javascript', { minSeverity: 'medium' }), []);
  assert.deepStrictEqual(ids('eval(x)', 'go'), []);
});

test('dependency advisories', () => {
  assert.ok(isVulnerable('4.17.20', [{ fixed: '4.17.21' }]));
  assert.ok(!isVulnerable('4.17.21', [{ fixed: '4.17.21' }]));
  const pkg = JSON.stringify({ dependencies: { lodash: '4.17.20', minimist: '^1.2.0', express: '4.18.2' } }, null, 2);
  const f = scanDependencies(pkg, 'package.json');
  assert.deepStrictEqual(f.map((x) => x.advisory).sort(), ['CVE-2021-23337', 'CVE-2021-44906']);
  const lodash = f.find((x) => x.advisory === 'CVE-2021-23337');
  const minimist = f.find((x) => x.advisory === 'CVE-2021-44906');
  assert.strictEqual(lodash.severity, 'high');
  assert.strictEqual(minimist.severity, 'high', 'range spec is downgraded one level from critical');
  const req = scanDependencies('requests==2.25.0\nflask>=3.0.0\npyyaml==5.3\n', 'requirements.txt');
  assert.deepStrictEqual(req.map((x) => x.advisory).sort(), ['CVE-2020-14343', 'CVE-2023-32681']);
  const lock = JSON.stringify({ packages: { '': {}, 'node_modules/a/node_modules/lodash': { version: '4.17.15' } } }, null, 2);
  assert.strictEqual(scanDependencies(lock, 'package-lock.json').length, 1);
  assert.deepStrictEqual(scanDependencies('{ not json', 'package.json'), []);
});

test('score and SARIF output', () => {
  const clean = summarize([]);
  assert.strictEqual(clean.score, 100);
  assert.strictEqual(clean.grade, 'A');
  const f = scanText(`eval(x)\nconst k="${AWS}"`, { lang: 'javascript' });
  const s = summarize(f);
  assert.ok(s.score < 100 && s.total === 2);
  const sarif = buildSarif([{ file: 'src/a.js', findings: f }], '1.0.0');
  assert.strictEqual(sarif.version, '2.1.0');
  assert.strictEqual(sarif.runs[0].results.length, 2);
  assert.ok(sarif.runs[0].tool.driver.rules.every((r) => r.properties['security-severity']));
  assert.strictEqual(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 1);
});

test('clean, realistic code produces no noise', () => {
  const src = `
import express from 'express';
import { createHash } from 'crypto';
const app = express();
const secret = process.env.JWT_SECRET;
app.get('/u/:id', async (req, res) => {
  const rows = await db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
  const etag = createHash('sha256').update(JSON.stringify(rows)).digest('hex');
  res.set('ETag', etag).json(rows);
});
const re = /(\\d+)/g; let m; while ((m = re.exec(text))) console.log(m[1]);
el.textContent = userName;
fetch('https://api.example.com/v1');
`;
  assert.deepStrictEqual(ids(src, 'typescript'), []);
});

test('performance: 20k lines under a few seconds', () => {
  const line = 'const value = compute(a, b) + helper(c); // ordinary code line number\n';
  const big = line.repeat(20000);
  const t = Date.now();
  scanText(big, { lang: 'javascript' });
  assert.ok(Date.now() - t < 6000, `took ${Date.now() - t}ms`);
});
