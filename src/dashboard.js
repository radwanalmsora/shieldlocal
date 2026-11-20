'use strict';
const vscode = require('vscode');

class Dashboard {
  constructor(context, handlers) {
    this.context = context;
    this.handlers = handlers;
    this.panel = null;
    this.data = null;
  }

  show(data) {
    this.data = data;
    if (this.panel) { this.panel.reveal(vscode.ViewColumn.Beside, true); this.update(data); return; }
    const media = vscode.Uri.joinPath(this.context.extensionUri, 'media');
    this.panel = vscode.window.createWebviewPanel('shieldlocal.dashboard', 'ShieldLocal Dashboard', vscode.ViewColumn.Beside,
      { enableScripts: true, localResourceRoots: [media], retainContextWhenHidden: true });
    this.panel.iconPath = vscode.Uri.joinPath(this.context.extensionUri, 'media', 'shield.svg');
    this.panel.webview.html = this.html(this.panel.webview, media);
    this.panel.onDidDispose(() => { this.panel = null; });
    this.panel.webview.onDidReceiveMessage((m) => {
      const h = this.handlers;
      switch (m.type) {
        case 'ready': this.update(this.data); break;
        case 'open': h.open(m.finding); break;
        case 'rescan': h.rescan(); break;
        case 'exportSarif': h.exportSarif(); break;
        case 'exportReport': h.exportReport(); break;
        case 'disableRule': h.disableRule(m.id); break;
      }
    });
  }

  update(data) {
    this.data = data;
    if (this.panel) this.panel.webview.postMessage({ type: 'data', data });
  }

  html(webview, media) {
    const nonce = [...Array(24)].map(() => Math.random().toString(36)[2]).join('');
    const css = webview.asWebviewUri(vscode.Uri.joinPath(media, 'dashboard.css'));
    const js = webview.asWebviewUri(vscode.Uri.joinPath(media, 'dashboard.js'));
    return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource}; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="${css}"><title>ShieldLocal</title></head>
<body>
<header>
  <div class="brand"><svg viewBox="0 0 24 24" width="26" height="26"><path d="M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="m8.5 12 2.5 2.5 4.5-5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
  <div><h1>ShieldLocal</h1><span id="sub">Offline security scanner</span></div></div>
  <div class="actions">
    <button id="rescan">Scan workspace</button>
    <button id="sarif" class="ghost">Export SARIF</button>
    <button id="md" class="ghost">Export report</button>
  </div>
</header>
<main id="app"></main>
<script nonce="${nonce}" src="${js}"></script>
</body></html>`;
  }
}

module.exports = { Dashboard };
