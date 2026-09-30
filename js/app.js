/**
 * PEVision — Main application controller
 */
(function () {
  'use strict';

  const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB

  const els = {
    navLinks: document.querySelectorAll('.nav-link'),
    sections: document.querySelectorAll('.page-section'),
    dropZone: document.getElementById('drop-zone'),
    fileInput: document.getElementById('file-input'),
    browseBtn: document.getElementById('browse-btn'),
    analyzeBtn: document.getElementById('analyze-btn'),
    clearBtn: document.getElementById('clear-btn'),
    fileMeta: document.getElementById('file-meta'),
    loading: document.getElementById('loading'),
    errorBox: document.getElementById('error-box'),
    results: document.getElementById('results'),
    resultTabs: document.getElementById('result-tabs'),
    resultPanels: document.getElementById('result-panels'),
    navToggle: document.getElementById('nav-toggle'),
    navMenu: document.getElementById('nav-menu'),
  };

  let selectedFile = null;
  let analysisData = null;

  // ── Navigation ──
  function showSection(id) {
    els.sections.forEach(s => s.classList.toggle('active', s.id === id));
    els.navLinks.forEach(l => l.classList.toggle('active', l.dataset.section === id));
    els.navMenu.classList.remove('open');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  els.navLinks.forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      showSection(link.dataset.section);
    });
  });

  els.navToggle?.addEventListener('click', () => {
    els.navMenu.classList.toggle('open');
  });

  // ── File handling ──
  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(2) + ' MB';
  }

  function setFile(file) {
    if (!file) return;
    if (file.size > MAX_FILE_SIZE) {
      showError('File exceeds 100 MB limit.');
      return;
    }
    selectedFile = file;
    els.fileMeta.innerHTML = `
      <div class="file-chip">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
        <span class="file-name">${escapeHtml(file.name)}</span>
        <span class="file-size">${formatSize(file.size)}</span>
      </div>`;
    els.analyzeBtn.disabled = false;
    hideError();
    els.results.classList.add('hidden');
  }

  function clearFile() {
    selectedFile = null;
    analysisData = null;
    els.fileInput.value = '';
    els.fileMeta.innerHTML = '';
    els.analyzeBtn.disabled = true;
    els.results.classList.add('hidden');
    hideError();
  }

  els.browseBtn.addEventListener('click', () => els.fileInput.click());
  els.fileInput.addEventListener('change', e => {
    if (e.target.files[0]) setFile(e.target.files[0]);
  });
  els.clearBtn.addEventListener('click', clearFile);

  // Drag & drop
  ['dragenter', 'dragover'].forEach(evt => {
    els.dropZone.addEventListener(evt, e => {
      e.preventDefault();
      els.dropZone.classList.add('drag-over');
    });
  });
  ['dragleave', 'drop'].forEach(evt => {
    els.dropZone.addEventListener(evt, e => {
      e.preventDefault();
      els.dropZone.classList.remove('drag-over');
    });
  });
  els.dropZone.addEventListener('drop', e => {
    const file = e.dataTransfer.files[0];
    if (file) setFile(file);
  });

  // ── Analysis ──
  els.analyzeBtn.addEventListener('click', async () => {
    if (!selectedFile) return;
    hideError();
    els.loading.classList.remove('hidden');
    els.results.classList.add('hidden');
    els.analyzeBtn.disabled = true;

    try {
      const buffer = await selectedFile.arrayBuffer();
      const parser = new PEParser(buffer, selectedFile.name);
      parser.parse(); // synchronous PE structure parsing
      analysisData = await parser.buildResult(); // async hash calculation
      renderResults(analysisData);
      els.results.classList.remove('hidden');
    } catch (err) {
      showError(err.message || 'Failed to analyze PE file.');
    } finally {
      els.loading.classList.add('hidden');
      els.analyzeBtn.disabled = !selectedFile;
    }
  });

  function showError(msg) {
    els.errorBox.textContent = msg;
    els.errorBox.classList.remove('hidden');
  }

  function hideError() {
    els.errorBox.classList.add('hidden');
  }

  function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  // ── Rendering ──
  function renderResults(data) {
    const tabs = [
      { id: 'overview', label: 'Overview', icon: '◈' },
      { id: 'headers', label: 'Headers', icon: '⬡' },
      { id: 'sections', label: 'Sections', icon: '▤' },
      { id: 'imports', label: 'Imports', icon: '⬇' },
      { id: 'exports', label: 'Exports', icon: '⬆' },
      { id: 'security', label: 'Security', icon: '⚠' },
      { id: 'directories', label: 'Directories', icon: '▦' },
    ];

    els.resultTabs.innerHTML = tabs.map((t, i) =>
      `<button class="tab-btn${i === 0 ? ' active' : ''}" data-tab="${t.id}">${t.icon} ${t.label}</button>`
    ).join('');

    els.resultPanels.innerHTML = `
      ${renderOverview(data)}
      ${renderHeaders(data)}
      ${renderSections(data)}
      ${renderImports(data)}
      ${renderExports(data)}
      ${renderSecurity(data)}
      ${renderDirectories(data)}
    `;

    els.resultTabs.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        els.resultTabs.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        els.resultPanels.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(`panel-${btn.dataset.tab}`).classList.add('active');
      });
    });
  }

  function kvGrid(rows) {
    return `<div class="kv-grid">${rows.map(([k, v]) =>
      `<div class="kv-key">${k}</div><div class="kv-val">${v}</div>`
    ).join('')}</div>`;
  }

  function renderOverview(data) {
    const s = data.summary;
    const alerts = [];
    if (data.suspiciousApis.length) alerts.push(`<span class="badge badge-warn">${data.suspiciousApis.length} Suspicious API(s)</span>`);
    if (s.rwxSections.length) alerts.push(`<span class="badge badge-danger">${s.rwxSections.length} RWX Section(s)</span>`);

    return `<div class="tab-panel active" id="panel-overview">
      <div class="overview-cards">
        <div class="stat-card"><div class="stat-label">Architecture</div><div class="stat-value">${s.architecture}</div></div>
        <div class="stat-card"><div class="stat-label">Sections</div><div class="stat-value">${s.sectionCount}</div></div>
        <div class="stat-card"><div class="stat-label">Imported DLLs</div><div class="stat-value">${s.importedDlls}</div></div>
        <div class="stat-card"><div class="stat-label">Exports</div><div class="stat-value">${s.exportCount}</div></div>
        <div class="stat-card"><div class="stat-label">GUI Program</div><div class="stat-value">${s.isGui ? 'Yes' : 'No'}</div></div>
        <div class="stat-card"><div class="stat-label">TLS</div><div class="stat-value">${data.tls.present ? 'Present' : 'None'}</div></div>
      </div>
      ${alerts.length ? `<div class="alert-row">${alerts.join('')}</div>` : ''}
      <h3 class="panel-title">File Information</h3>
      ${kvGrid([
        ['File Name', escapeHtml(data.fileInfo.fileName)],
        ['File Size', data.fileInfo.fileSize.toLocaleString() + ' bytes'],
        ['MD5', `<code class="hash">${data.hashes.MD5}</code>`],
        ['SHA-1', `<code class="hash">${data.hashes.SHA1}</code>`],
        ['SHA-256', `<code class="hash">${data.hashes.SHA256}</code>`],
        ['ImpHash', `<code class="hash">${data.imphash || 'N/A'}</code>`],
      ])}
    </div>`;
  }

  function renderHeaders(data) {
    return `<div class="tab-panel" id="panel-headers">
      <h3 class="panel-title">DOS Header</h3>
      ${kvGrid([
        ['e_magic', data.dosHeader.e_magic],
        ['e_lfanew', data.dosHeader.e_lfanew],
      ])}
      <h3 class="panel-title">NT Header</h3>
      ${kvGrid([['Signature', data.ntHeader.signature]])}
      <h3 class="panel-title">File Header</h3>
      ${kvGrid([
        ['Machine', data.fileHeader.machine],
        ['Number Of Sections', data.fileHeader.numberOfSections],
        ['Timestamp', data.fileHeader.timestamp],
        ['Characteristics', data.fileHeader.characteristics],
      ])}
      <h3 class="panel-title">Optional Header</h3>
      ${kvGrid([
        ['Entry Point', data.optionalHeader.entryPoint],
        ['Image Base', data.optionalHeader.imageBase],
        ['Section Alignment', data.optionalHeader.sectionAlignment],
        ['File Alignment', data.optionalHeader.fileAlignment],
        ['Size Of Image', data.optionalHeader.sizeOfImage],
        ['Size Of Headers', data.optionalHeader.sizeOfHeaders],
        ['Subsystem', data.optionalHeader.subsystem],
      ])}
    </div>`;
  }

  function renderSections(data) {
    const rows = data.sections.map(s => `
      <tr class="${s.rwx ? 'row-danger' : ''}">
        <td><code>${escapeHtml(s.name)}</code></td>
        <td><code>0x${s.virtualAddress.toString(16)}</code></td>
        <td><code>0x${s.virtualSize.toString(16)}</code></td>
        <td><code>0x${s.rawSize.toString(16)}</code></td>
        <td>${s.entropy}</td>
        <td><code>0x${s.characteristics.toString(16)}</code></td>
        <td><span class="perm-badge">${s.permissions}</span></td>
        <td>${s.rwx ? '<span class="badge badge-danger">RWX</span>' : ''}</td>
      </tr>`).join('');

    return `<div class="tab-panel" id="panel-sections">
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr>
            <th>Name</th><th>Virtual Addr</th><th>Virtual Size</th><th>Raw Size</th>
            <th>Entropy</th><th>Characteristics</th><th>Perms</th><th>Flags</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`;
  }

  function renderImports(data) {
    if (!data.imports.length) {
      return `<div class="tab-panel" id="panel-imports"><p class="empty-msg">No imports found.</p></div>`;
    }
    const blocks = data.imports.map(entry => {
      const fns = entry.functions.map(fn => {
        const suspicious = PEVisionConstants.SUSPICIOUS_APIS.has(fn.name);
        return `<li class="${suspicious ? 'suspicious-api' : ''}">${escapeHtml(fn.name)}${suspicious ? ' ⚠' : ''}</li>`;
      }).join('');
      return `<div class="import-block">
        <div class="import-dll">${escapeHtml(entry.dll)}</div>
        <ul class="import-list">${fns}</ul>
      </div>`;
    }).join('');

    return `<div class="tab-panel" id="panel-imports">${blocks}</div>`;
  }

  function renderExports(data) {
    if (!data.exports.length) {
      return `<div class="tab-panel" id="panel-exports"><p class="empty-msg">No exports found.</p></div>`;
    }
    const rows = data.exports.map(e => `
      <tr>
        <td>${e.ordinal}</td>
        <td><code>0x${e.rva.toString(16)}</code></td>
        <td><code>${escapeHtml(e.name)}</code></td>
      </tr>`).join('');

    return `<div class="tab-panel" id="panel-exports">
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Ordinal</th><th>RVA</th><th>Name</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`;
  }

  function renderSecurity(data) {
    const apiList = data.suspiciousApis.length
      ? data.suspiciousApis.map(a => `<li class="suspicious-api">${escapeHtml(a)}</li>`).join('')
      : '<li class="safe-msg">No suspicious APIs detected.</li>';

    const rwxList = data.summary.rwxSections.length
      ? data.summary.rwxSections.map(n => `<li class="suspicious-api">${escapeHtml(n)} — Read/Write/Execute</li>`).join('')
      : '<li class="safe-msg">No RWX sections detected.</li>';

    return `<div class="tab-panel" id="panel-security">
      <h3 class="panel-title">Suspicious API Check</h3>
      <ul class="security-list">${apiList}</ul>
      <h3 class="panel-title">RWX Section Check</h3>
      <ul class="security-list">${rwxList}</ul>
      <h3 class="panel-title">TLS Information</h3>
      ${kvGrid([['TLS Directory', data.tls.present ? 'Present' : 'Not Present']])}
    </div>`;
  }

  function renderDirectories(data) {
    const rows = data.dataDirectories.map(d => `
      <tr>
        <td><code>${d.name}</code></td>
        <td><code>${d.virtualAddress ? '0x' + d.virtualAddress.toString(16) : '0x0'}</code></td>
        <td><code>${d.size ? '0x' + d.size.toString(16) : '0x0'}</code></td>
      </tr>`).join('');

    return `<div class="tab-panel" id="panel-directories">
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Directory</th><th>RVA</th><th>Size</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`;
  }
})();
