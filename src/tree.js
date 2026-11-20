'use strict';
const vscode = require('vscode');
const { SEVERITIES } = require('./scanner');

const ICON = {
  critical: ['flame', 'testing.iconFailed'],
  high: ['error', 'problemsErrorIcon.foreground'],
  medium: ['warning', 'problemsWarningIcon.foreground'],
  low: ['info', 'problemsInfoIcon.foreground'],
  info: ['lightbulb', 'foreground'],
};

class FindingsTree {
  constructor() {
    this._emitter = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._emitter.event;
    this.groups = {};
  }

  refresh(store) {
    const g = {};
    for (const e of store.values()) {
      for (const f of e.findings) (g[f.severity] ||= []).push({ ...f, file: e.file, uri: e.uri.toString() });
    }
    for (const k in g) g[k].sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
    this.groups = g;
    this._emitter.fire();
  }

  getTreeItem(el) {
    if (el.kind === 'group') {
      const item = new vscode.TreeItem(
        `${el.severity[0].toUpperCase()}${el.severity.slice(1)}`,
        el.count > 25 ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.Expanded
      );
      item.description = String(el.count);
      item.iconPath = new vscode.ThemeIcon(ICON[el.severity][0], new vscode.ThemeColor(ICON[el.severity][1]));
      item.contextValue = 'group';
      return item;
    }
    const f = el.f;
    const item = new vscode.TreeItem(f.title, vscode.TreeItemCollapsibleState.None);
    item.description = `${f.file}:${f.line + 1}`;
    item.iconPath = new vscode.ThemeIcon(ICON[f.severity][0], new vscode.ThemeColor(ICON[f.severity][1]));
    const md = new vscode.MarkdownString(`**${f.title}**\n\n${f.message}\n\n**Fix:** ${f.remediation}`);
    item.tooltip = md;
    item.command = { command: 'shieldlocal.openFinding', title: 'Open', arguments: [f] };
    return item;
  }

  getChildren(el) {
    if (!el) {
      return SEVERITIES.filter((s) => this.groups[s]?.length).map((s) => ({ kind: 'group', severity: s, count: this.groups[s].length }));
    }
    if (el.kind === 'group') return this.groups[el.severity].slice(0, 500).map((f) => ({ kind: 'finding', f }));
    return [];
  }
}

module.exports = { FindingsTree };
