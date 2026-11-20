'use strict';
const vscode = require('vscode');
const path = require('path');
const { scanText, summarize, langFromFile, SEVERITIES, SEVERITY_RANK, SCANNABLE_EXTENSIONS } = require('./scanner');
const { scanDependencies, isDependencyFile } = require('./deps');
const { RULES } = require('./rules');
const { buildSarif } = require('./sarif');
const { buildMarkdown } = require('./report');
const { FindingsTree } = require('./tree');
const { Dashboard } = require('./dashboard');

const SUPPORTED_LANGS = new Set([
  'javascript', 'typescript', 'javascriptreact', 'typescriptreact', 'vue', 'svelte', 'html',
  'python', 'php', 'java', 'go', 'csharp', 'ruby', 'shellscript', 'dockerfile',
  'yaml', 'json', 'jsonc', 'properties', 'ini', 'toml', 'dotenv',
]);
const HASH_COMMENT = new Set(['python', 'ruby', 'shellscript', 'dockerfile', 'yaml', 'properties', 'ini', 'toml', 'dotenv']);
const DIAG_SEVERITY = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};

/** @type {Map<string, {uri: vscode.Uri, file: string, findings: any[]}>} */
const store = new Map();
let diagnostics, statusBar, tree, dashboard, output;
const timers = new Map();

const cfg = () => vscode.workspace.getConfiguration('shieldlocal');
const relPath = (uri) => vscode.workspace.asRelativePath(uri, false);
const decoder = new TextDecoder('utf-8');

function languageFor(doc) {
  const byName = langFromFile(doc.fileName);
  if (byName === 'dotenv' || byName === 'dockerfile') return byName;
  return doc.languageId === 'jsonc' ? 'json' : doc.languageId;
}

function isScannable(doc) {
  if (!cfg().get('enable', true)) return false;
  if (!['file', 'untitled', 'vscode-remote', 'vscode-vfs', 'vscode-userdata'].includes(doc.uri.scheme)) return false;
  return SUPPORTED_LANGS.has(languageFor(doc)) || isDependencyFile(doc.fileName);
}

function customAdvisories() {
  const raw = cfg().get('customAdvisories', []);
  return Array.isArray(raw) ? raw.filter((a) => a && a.eco && a.name && a.id && a.ranges) : [];
}

function analyze(text, fileName, lang) {
  const c = cfg();
  let found = [];
  if (isDependencyFile(fileName)) {
    if (c.get('scanDependencies', true)) found = scanDependencies(text, fileName, customAdvisories());
  } else {
    found = scanText(text, {
      lang, file: fileName,
      disabledRules: c.get('disabledRules', []),
      minSeverity: c.get('minimumSeverity', 'low'),
    });
  }
  const min = SEVERITY_RANK[c.get('minimumSeverity', 'low')] ?? 1;
  return found.filter((f) => SEVERITY_RANK[f.severity] >= min);
}

function publish(uri, findings) {
  const key = uri.toString();
  if (!findings.length) {
    store.delete(key);
    diagnostics.delete(uri);
  } else {
    store.set(key, { uri, file: relPath(uri), findings });
    diagnostics.set(uri, findings.map(toDiagnostic));
  }
}

function toDiagnostic(f) {
  const range = new vscode.Range(f.line, f.col, f.line, Math.max(f.endCol, f.col + 1));
  const d = new vscode.Diagnostic(range, `${f.title}\n${f.message}\nFix: ${f.remediation}`, DIAG_SEVERITY[f.severity]);
  d.source = 'ShieldLocal';
  d.code = f.cwe
    ? { value: f.ruleId, target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${f.cwe}.html`) }
    : f.ruleId;
  if (f.severity === 'info') d.tags = [];
  return d;
}

function scanDocument(doc) {
  if (!isScannable(doc)) {
    publish(doc.uri, []);
    return;
  }
  const maxKB = cfg().get('maxFileSizeKB', 1024);
  if (doc.getText().length > maxKB * 1024) return;
  publish(doc.uri, analyze(doc.getText(), doc.fileName, languageFor(doc)));
  refreshUi();
}

function scheduleScan(doc) {
  const key = doc.uri.toString();
  clearTimeout(timers.get(key));
  timers.set(key, setTimeout(() => { timers.delete(key); scanDocument(doc); }, 450));
}

/* ───────────── UI refresh ───────────── */
let uiTimer;
function refreshUi() {
  clearTimeout(uiTimer);
  uiTimer = setTimeout(() => {
    const all = allFindings();
    const s = summarize(all);
    tree.refresh(store);
    vscode.commands.executeCommand('setContext', 'shieldlocal.hasFindings', all.length > 0);
    if (dashboard) dashboard.update(buildDashboardData());
    if (!cfg().get('enable', true)) { statusBar.hide(); return; }
    statusBar.text = all.length ? `$(shield) ${all.length}` : '$(shield) Clean';
    const md = new vscode.MarkdownString(
      `**ShieldLocal** — score **${s.score}/100** (${s.grade})\n\n` +
      SEVERITIES.filter((x) => s.bySeverity[x]).map((x) => `- ${x}: ${s.bySeverity[x]}`).join('\n') +
      (all.length ? '' : '\nNo issues in scanned files.') + '\n\n_Click to open the dashboard_'
    );
    statusBar.tooltip = md;
    statusBar.backgroundColor = s.bySeverity.critical
      ? new vscode.ThemeColor('statusBarItem.errorBackground')
      : s.bySeverity.high ? new vscode.ThemeColor('statusBarItem.warningBackground') : undefined;
    statusBar.show();
  }, 120);
}

const allFindings = () => [...store.values()].flatMap((e) => e.findings);

function buildDashboardData() {
  const items = [...store.values()];
  const findings = [];
  for (const e of items) {
    for (const f of e.findings) {
      if (findings.length >= 3000) break;
      findings.push({ ...f, file: e.file, uri: e.uri.toString() });
    }
  }
  const all = items.flatMap((e) => e.findings);
  const topFiles = items
    .map((e) => ({ file: e.file, count: e.findings.length, worst: SEVERITIES.find((s) => e.findings.some((f) => f.severity === s)) }))
    .sort((a, b) => b.count - a.count).slice(0, 6);
  return { summary: summarize(all), findings, topFiles, rules: RULES.length, generated: new Date().toLocaleTimeString() };
}

/* ───────────── Workspace scan ───────────── */
function buildGlobs() {
  const exts = SCANNABLE_EXTENSIONS.join(',');
  const include = `**/{*.{${exts}},.env,.env.*,Dockerfile,Dockerfile.*,package-lock.json,requirements*.txt}`;
  const defaults = ['node_modules', '.git', 'dist', 'build', 'out', '.venv', 'venv', 'vendor', '__pycache__', 'coverage', '.next', 'target'];
  const user = cfg().get('excludeGlobs', []);
  const parts = [`**/{${defaults.join(',')}}/**`, '**/*.min.js', '**/*.map', '**/*.lock', ...user];
  return { include, exclude: `{${parts.join(',')}}` };
}

async function scanWorkspace() {
  if (!vscode.workspace.workspaceFolders) {
    vscode.window.showWarningMessage('ShieldLocal: open a folder first to scan a workspace.');
    return;
  }
  const { include, exclude } = buildGlobs();
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'ShieldLocal: scanning workspace', cancellable: true },
    async (progress, token) => {
      const files = await vscode.workspace.findFiles(include, exclude, 8000);
      const maxBytes = cfg().get('maxFileSizeKB', 1024) * 1024;
      let done = 0, skipped = 0;
      for (const uri of files) {
        if (token.isCancellationRequested) break;
        try {
          const bytes = await vscode.workspace.fs.readFile(uri);
          if (bytes.length > maxBytes || bytes.subarray(0, 4000).includes(0)) { skipped++; continue; }
          const open = vscode.workspace.textDocuments.find((d) => d.uri.toString() === uri.toString());
          const text = open ? open.getText() : decoder.decode(bytes);
          const lang = langFromFile(uri.fsPath) || 'plaintext';
          publish(uri, analyze(text, uri.fsPath, lang));
        } catch (_) { skipped++; }
        done++;
        if (done % 25 === 0) {
          progress.report({ message: `${done}/${files.length} files`, increment: (25 / Math.max(files.length, 1)) * 100 });
          await new Promise((r) => setImmediate(r));
        }
      }
      refreshUi();
      const s = summarize(allFindings());
      const msg = s.total
        ? `ShieldLocal: ${s.total} finding(s) in ${store.size} file(s) · score ${s.score}/100. Scanned ${done} files${skipped ? `, skipped ${skipped}` : ''}.`
        : `ShieldLocal: no issues found in ${done} files. 🎉`;
      const pick = await vscode.window.showInformationMessage(msg, 'Open Dashboard');
      if (pick) dashboard.show(buildDashboardData());
    }
  );
}

/* ───────────── Export ───────────── */
function exportItems() {
  return [...store.values()].map((e) => ({ file: e.file, findings: e.findings }));
}

async function exportFile(kind) {
  if (!store.size) {
    const pick = await vscode.window.showInformationMessage('ShieldLocal: nothing to export yet. Scan the workspace first?', 'Scan Workspace');
    if (pick) await scanWorkspace();
    if (!store.size) return;
  }
  const root = vscode.workspace.workspaceFolders?.[0]?.uri;
  const name = kind === 'sarif' ? 'shieldlocal.sarif' : 'shieldlocal-report.md';
  const target = await vscode.window.showSaveDialog({
    defaultUri: root ? vscode.Uri.joinPath(root, name) : undefined,
    filters: kind === 'sarif' ? { SARIF: ['sarif', 'json'] } : { Markdown: ['md'] },
  });
  if (!target) return;
  const version = vscode.extensions.getExtension('radwanalmsora.shieldlocal')?.packageJSON.version;
  const content = kind === 'sarif'
    ? JSON.stringify(buildSarif(exportItems(), version), null, 2)
    : buildMarkdown(exportItems());
  await vscode.workspace.fs.writeFile(target, Buffer.from(content, 'utf8'));
  const pick = await vscode.window.showInformationMessage(`ShieldLocal: report saved to ${path.basename(target.fsPath)}`, 'Open');
  if (pick) vscode.window.showTextDocument(target);
}

/* ───────────── Code actions ───────────── */
class QuickFixProvider {
  provideCodeActions(doc, _range, context) {
    const entry = store.get(doc.uri.toString());
    if (!entry) return [];
    const actions = [];
    for (const diag of context.diagnostics) {
      if (diag.source !== 'ShieldLocal') continue;
      const ruleId = typeof diag.code === 'object' ? diag.code.value : diag.code;
      const f = entry.findings.find((x) => x.ruleId === ruleId && x.line === diag.range.start.line && x.col === diag.range.start.character);
      if (!f) continue;

      if (f.fix) {
        const a = new vscode.CodeAction(`ShieldLocal: ${f.fix.title}`, vscode.CodeActionKind.QuickFix);
        a.edit = new vscode.WorkspaceEdit();
        a.edit.replace(doc.uri, new vscode.Range(f.line, f.fix.col, f.line, f.fix.endCol), f.fix.newText);
        a.diagnostics = [diag];
        a.isPreferred = true;
        actions.push(a);
      }
      const lang = languageFor(doc);
      if (lang !== 'json' && doc.languageId !== 'jsonc') {
        const style = HASH_COMMENT.has(lang) ? ['# ', ''] : lang === 'html' ? ['<!-- ', ' -->'] : ['// ', ''];
        const ignore = new vscode.CodeAction('ShieldLocal: Ignore this finding (adds comment)', vscode.CodeActionKind.QuickFix);
        ignore.edit = new vscode.WorkspaceEdit();
        const eol = doc.lineAt(f.line).range.end;
        ignore.edit.insert(doc.uri, eol, `  ${style[0]}shieldlocal-ignore: ${f.ruleId}${style[1]}`);
        ignore.diagnostics = [diag];
        actions.push(ignore);
      }
      const off = new vscode.CodeAction(`ShieldLocal: Disable rule "${f.ruleId}" in this workspace`, vscode.CodeActionKind.QuickFix);
      off.command = { command: 'shieldlocal.disableRule', title: 'Disable rule', arguments: [f.ruleId] };
      off.diagnostics = [diag];
      actions.push(off);
    }
    return actions;
  }
}

/* ───────────── Activation ───────────── */
function activate(context) {
  output = vscode.window.createOutputChannel('ShieldLocal');
  diagnostics = vscode.languages.createDiagnosticCollection('shieldlocal');
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  statusBar.command = 'shieldlocal.openDashboard';
  tree = new FindingsTree();
  dashboard = new Dashboard(context, {
    open: openLocation,
    rescan: () => scanWorkspace(),
    exportSarif: () => exportFile('sarif'),
    exportReport: () => exportFile('md'),
    disableRule: (id) => disableRule(id),
  });

  const selector = [{ scheme: 'file' }, { scheme: 'untitled' }, { scheme: 'vscode-remote' }, { scheme: 'vscode-vfs' }];
  context.subscriptions.push(
    output, diagnostics, statusBar,
    vscode.window.createTreeView('shieldlocal.findings', { treeDataProvider: tree, showCollapseAll: true }),
    vscode.languages.registerCodeActionsProvider(selector, new QuickFixProvider(), { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
    vscode.workspace.onDidOpenTextDocument(scanDocument),
    vscode.workspace.onDidSaveTextDocument(scanDocument),
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (cfg().get('scanOnType', true) && e.contentChanges.length) scheduleScan(e.document);
    }),
    vscode.workspace.onDidCloseTextDocument((doc) => {
      // keep workspace-scan results; only drop transient untitled buffers
      if (doc.uri.scheme === 'untitled') { publish(doc.uri, []); refreshUi(); }
    }),
    vscode.workspace.onDidDeleteFiles((e) => { e.files.forEach((u) => publish(u, [])); refreshUi(); }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (!e.affectsConfiguration('shieldlocal')) return;
      if (!cfg().get('enable', true)) { store.clear(); diagnostics.clear(); }
      else vscode.workspace.textDocuments.forEach(scanDocument);
      refreshUi();
    }),

    vscode.commands.registerCommand('shieldlocal.scanWorkspace', scanWorkspace),
    vscode.commands.registerCommand('shieldlocal.scanFile', () => {
      const ed = vscode.window.activeTextEditor;
      if (!ed) return vscode.window.showWarningMessage('ShieldLocal: no active editor.');
      scanDocument(ed.document);
      const n = store.get(ed.document.uri.toString())?.findings.length || 0;
      vscode.window.showInformationMessage(n ? `ShieldLocal: ${n} finding(s) in this file.` : 'ShieldLocal: this file looks clean ✅');
    }),
    vscode.commands.registerCommand('shieldlocal.openDashboard', () => dashboard.show(buildDashboardData())),
    vscode.commands.registerCommand('shieldlocal.exportSarif', () => exportFile('sarif')),
    vscode.commands.registerCommand('shieldlocal.exportReport', () => exportFile('md')),
    vscode.commands.registerCommand('shieldlocal.clear', () => { store.clear(); diagnostics.clear(); refreshUi(); }),
    vscode.commands.registerCommand('shieldlocal.disableRule', disableRule),
    vscode.commands.registerCommand('shieldlocal.openFinding', openLocation),
    vscode.commands.registerCommand('shieldlocal.showRules', async () => {
      const disabled = new Set(cfg().get('disabledRules', []));
      const pick = await vscode.window.showQuickPick(
        RULES.map((r) => ({
          label: `${disabled.has(r.id) ? '$(circle-slash)' : '$(shield)'} ${r.title}`,
          description: `${r.severity} · ${r.category}${r.cwe ? ` · CWE-${r.cwe}` : ''}`,
          detail: r.message, id: r.id,
        })),
        { placeHolder: `${RULES.length} built-in rules — select one to toggle it`, matchOnDescription: true, matchOnDetail: true }
      );
      if (pick) await toggleRule(pick.id);
    })
  );

  vscode.workspace.textDocuments.forEach(scanDocument);
  refreshUi();
  output.appendLine(`ShieldLocal ready · ${RULES.length} rules · fully offline, no telemetry.`);
}

async function toggleRule(id) {
  const list = new Set(cfg().get('disabledRules', []));
  list.has(id) ? list.delete(id) : list.add(id);
  await cfg().update('disabledRules', [...list], vscode.ConfigurationTarget.Workspace);
}
async function disableRule(id) {
  const list = new Set(cfg().get('disabledRules', []));
  list.add(id);
  await cfg().update('disabledRules', [...list], vscode.ConfigurationTarget.Workspace);
  vscode.window.showInformationMessage(`ShieldLocal: rule "${id}" disabled for this workspace.`);
}

async function openLocation(arg) {
  try {
    const uri = vscode.Uri.parse(arg.uri);
    const doc = await vscode.workspace.openTextDocument(uri);
    const pos = new vscode.Position(arg.line, arg.col || 0);
    await vscode.window.showTextDocument(doc, { selection: new vscode.Range(pos, pos), preview: true });
  } catch (e) {
    vscode.window.showWarningMessage(`ShieldLocal: could not open file (${e.message}).`);
  }
}

function deactivate() { timers.forEach(clearTimeout); }

module.exports = { activate, deactivate };
