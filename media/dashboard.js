(function () {
  const vscode = acquireVsCodeApi();
  const COLORS = { critical: '#ff4d6d', high: '#ff8a3d', medium: '#f5c542', low: '#4da3ff', info: '#8b95a7' };
  const ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  let data = null;
  const state = Object.assign({ sev: new Set(ORDER), q: '' }, {});
  const app = document.getElementById('app');

  const el = (tag, attrs, ...kids) => {
    const n = document.createElement(tag);
    for (const k in (attrs || {})) {
      if (k === 'class') n.className = attrs[k];
      else if (k === 'style') n.setAttribute('style', attrs[k]);
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), attrs[k]);
      else n.setAttribute(k, attrs[k]);
    }
    for (const kid of kids.flat()) if (kid != null) n.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    return n;
  };
  const svg = (html) => { const d = document.createElement('div'); d.innerHTML = html; return d.firstChild; };

  function ring(score) {
    const r = 62, c = 2 * Math.PI * r, off = c * (1 - score / 100);
    const col = score >= 80 ? '#34d3b4' : score >= 55 ? '#f5c542' : '#ff4d6d';
    const wrap = el('div', { class: 'ring' });
    wrap.append(svg(`<svg width="150" height="150" viewBox="0 0 150 150"><circle cx="75" cy="75" r="${r}" fill="none" stroke="rgba(128,128,128,.2)" stroke-width="12"/><circle cx="75" cy="75" r="${r}" fill="none" stroke="${col}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${off}"/></svg>`));
    wrap.append(el('div', { class: 'num' }, el('b', {}, score), el('small', {}, '/ 100')));
    return wrap;
  }

  function bars(obj, colorOf, order) {
    const keys = order || Object.keys(obj).sort((a, b) => obj[b] - obj[a]);
    const max = Math.max(1, ...keys.map((k) => obj[k] || 0));
    return keys.map((k) => el('div', { class: 'bar' },
      el('span', {}, k),
      el('div', { class: 'track' }, el('div', { class: 'fill', style: `width:${((obj[k] || 0) / max) * 100}%;background:${colorOf(k)}` })),
      el('span', {}, obj[k] || 0)));
  }

  function render() {
    app.replaceChildren();
    if (!data) return;
    const s = data.summary;
    if (!s.total) {
      app.append(el('div', { class: 'card empty' }, el('div', { class: 'big' }, '🛡️'), el('h2', {}, 'No findings'),
        'Nothing suspicious in the scanned files. Run a workspace scan to check everything.'));
      app.append(el('footer', {}, `${data.rules} rules · updated ${data.generated} · 100% offline`));
      return;
    }
    const palette = ['#34d3b4', '#4da3ff', '#a78bfa', '#f472b6', '#f5c542', '#fb923c', '#94a3b8'];
    const catColor = (k) => palette[Math.abs([...k].reduce((a, c) => a + c.charCodeAt(0), 0)) % palette.length];

    const scoreCard = el('div', { class: 'card score' }, el('h2', {}, 'Security score'), ring(s.score),
      el('div', { class: 'grade' }, `Grade ${s.grade} · ${s.total} finding${s.total === 1 ? '' : 's'}`));
    const sevCard = el('div', { class: 'card' }, el('h2', {}, 'By severity'), bars(s.bySeverity, (k) => COLORS[k], ORDER));
    const catCard = el('div', { class: 'card' }, el('h2', {}, 'By category'), bars(s.byCategory, catColor));
    app.append(el('div', { class: 'grid' }, scoreCard, sevCard, catCard));

    const files = el('div', { class: 'card files' }, el('h2', {}, 'Most affected files'),
      data.topFiles.map((f) => el('div', { class: 'row' },
        el('span', { class: 'name', title: f.file }, el('i', { class: 'dot', style: `background:${COLORS[f.worst] || '#888'}` }), f.file),
        el('b', {}, f.count))));
    app.append(files);

    const toolbar = el('div', { class: 'toolbar' },
      ORDER.map((k) => el('span', { class: 'chip' + (state.sev.has(k) ? ' on' : ''), onclick: () => { state.sev.has(k) ? state.sev.delete(k) : state.sev.add(k); render(); } }, `${k} ${s.bySeverity[k]}`)),
      el('input', { type: 'search', placeholder: 'Filter by file, rule or text…', value: state.q, oninput: (e) => { state.q = e.target.value; renderTable(); } }));
    const holder = el('div', { id: 'tbl' });
    app.append(el('div', { class: 'card', style: 'margin-top:14px' }, el('h2', {}, 'Findings'), toolbar, holder));
    renderTable();
    app.append(el('footer', {}, `${data.rules} built-in rules · updated ${data.generated} · analysis ran 100% on your machine`));
  }

  function renderTable() {
    const holder = document.getElementById('tbl');
    if (!holder) return;
    const q = state.q.toLowerCase();
    const rows = data.findings.filter((f) => state.sev.has(f.severity) &&
      (!q || (f.file + f.title + f.message + f.category).toLowerCase().includes(q)));
    const tb = el('tbody');
    rows.slice(0, 400).forEach((f) => {
      const tr = el('tr', { class: 'f', onclick: (e) => { e.currentTarget.classList.toggle('open'); } },
        el('td', {}, el('span', { class: 'sev', style: `background:${COLORS[f.severity]}` }, f.severity)),
        el('td', {}, el('b', {}, f.title), el('div', { class: 'detail' },
          el('div', {}, f.message), el('div', { style: 'margin-top:6px' }, el('b', {}, 'Fix: '), f.remediation),
          el('div', { style: 'margin-top:6px' }, el('code', {}, f.snippet)),
          el('div', { style: 'margin-top:8px;display:flex;gap:8px' },
            el('button', { onclick: (e) => { e.stopPropagation(); vscode.postMessage({ type: 'open', finding: f }); } }, 'Go to code'),
            el('button', { class: 'ghost', onclick: (e) => { e.stopPropagation(); vscode.postMessage({ type: 'disableRule', id: f.ruleId }); } }, 'Disable rule')))),
        el('td', { class: 'loc' }, `${f.file}:${f.line + 1}`),
        el('td', {}, f.cwe ? `CWE-${f.cwe}` : f.advisory || ''));
      tb.append(tr);
    });
    const table = el('table', {}, el('thead', {}, el('tr', {}, el('th', {}, 'Severity'), el('th', {}, 'Issue'), el('th', {}, 'Location'), el('th', {}, 'Ref'))), tb);
    holder.replaceChildren(rows.length ? table : el('div', { class: 'empty' }, 'No findings match the filter.'));
    if (rows.length > 400) holder.append(el('div', { class: 'empty' }, `Showing 400 of ${rows.length}. Narrow the filter or export the full report.`));
  }

  document.getElementById('rescan').onclick = () => vscode.postMessage({ type: 'rescan' });
  document.getElementById('sarif').onclick = () => vscode.postMessage({ type: 'exportSarif' });
  document.getElementById('md').onclick = () => vscode.postMessage({ type: 'exportReport' });
  window.addEventListener('message', (e) => { if (e.data.type === 'data') { data = e.data.data; render(); } });
  vscode.postMessage({ type: 'ready' });
})();
