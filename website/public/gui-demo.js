class GilbrtGuiDemo extends HTMLElement {
  constructor() {
    super();
    this.root = this.attachShadow({ mode: 'open' });
    this.report = null;
    this.page = 'overview';
    this.busy = false;
    this.ready = this.load();
  }
  async load() {
    const response = await fetch('/gui-demo.html');
    if (!response.ok) throw new Error('GUI template unavailable');
    const template = document.createElement('template');
    // This is a static application-owned template, never user/README content.
    template.innerHTML = await response.text();
    for (const href of ['/gui-demo.css', '/gui-demo-host.css']) {
      const link = document.createElement('link'); link.rel = 'stylesheet'; link.href = href; this.root.append(link);
    }
    this.root.append(template.content.cloneNode(true));
    this.queryAll('[data-page]').forEach(item => item.addEventListener('click', event => { event.preventDefault(); this.showPage(item.dataset.page); }));
    this.queryAll('[data-go]').forEach(item => item.addEventListener('click', () => this.showPage(item.dataset.go)));
    this.queryAll('[data-severity]').forEach(item => item.addEventListener('click', () => { this.query('#severity').value = item.dataset.severity; this.showPage('findings'); this.renderFindings(); }));
    for (const id of ['search', 'severity', 'category']) this.query(`#${id}`).addEventListener('input', () => this.renderFindings());
    this.query('#clear-filters').addEventListener('click', () => { this.query('#search').value = ''; this.query('#severity').value = 'all'; this.query('#category').value = 'all'; this.renderFindings(); });
    this.queryAll('[data-close]').forEach(button => button.addEventListener('click', () => button.closest('dialog').close()));
    this.query('#export-top').addEventListener('click', () => this.query('#export-dialog').showModal());
    this.query('#download-report').addEventListener('click', () => { this.exportReport(); this.query('#export-dialog').close(); });
    this.query('#new-audit').addEventListener('click', () => this.dispatchEvent(new CustomEvent('demo-replay', { bubbles: true })));
    this.showPage('overview');
  }
  query(selector) { return this.root.querySelector(selector); }
  queryAll(selector) { return [...this.root.querySelectorAll(selector)]; }
  node(tag, text, className) {
    const element = document.createElement(tag); if (text !== undefined) element.textContent = text; if (className) element.className = className; return element;
  }
  icon(name) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); svg.classList.add('icon'); svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(svg.namespaceURI, 'use'); use.setAttribute('href', `#i-${name}`); svg.append(use); return svg;
  }
  async setReport(report) {
    await this.ready; this.report = report;
    this.query('#target-name').textContent = new URL(report.target).host;
    this.query('#target-meta').textContent = 'Synthetic fixture · source, headers and TLS';
    this.query('#target-status').textContent = 'Sample complete';
    this.query('#target-status').setAttribute('role', 'status');
    // Set the use element, rather than replacing the shared icon.
    this.query('#session-icon use').setAttribute('href', '#i-globe');
    this.query('#critical-count').textContent = report.findings.filter(f => f.severity === 'Critical').length;
    this.query('#warning-count').textContent = report.findings.filter(f => f.severity === 'Warning').length;
    this.query('#info-count').textContent = report.findings.filter(f => f.severity === 'Info').length;
    this.query('#resource-count').textContent = report.coverage.resources_checked;
    this.query('#resource-summary').textContent = 'Synthetic fixture';
    this.query('#nav-count').textContent = report.findings.length; this.query('#nav-count').hidden = false;
    const category = this.query('#category'); category.replaceChildren(this.option('all', 'All categories'));
    for (const value of new Set(report.findings.map(f => f.category))) category.append(this.option(value, value));
    this.query('#severity').value = 'all'; this.query('#search').value = '';
    this.query('#priority-list').replaceChildren(...report.findings.slice(0, 4).map(f => this.findingRow(f)));
    this.query('#run-details').replaceChildren(...[['Source', 'Synthetic fixture'], ['Resources', '12 / 12'], ['Checks', 'Source, headers, TLS'], ['Evidence', 'Redacted'], ['Target requests', 'None']].map(([label, value]) => {
      const row = this.node('div'); row.append(this.node('dt', label), this.node('dd', value)); return row;
    }));
    this.query('#activity-events').replaceChildren(...['Sample resources loaded', 'Example source and headers reviewed', 'Five sample findings prepared'].map((text, index) => {
      const row = this.node('div'); row.append(this.node('span', `00:0${index}`), this.node('strong', text)); return row;
    }));
    this.renderFindings(); this.renderResources();
  }
  option(value, text) { const option = this.node('option', text); option.value = value; return option; }
  findingRow(finding) {
    const row = this.node('button', undefined, 'finding-row'); row.type = 'button';
    const copy = this.node('span', undefined, 'finding-copy'); copy.append(this.node('span', finding.title, 'finding-title'), this.node('span', finding.resource, 'finding-meta'));
    row.append(this.node('span', finding.severity, `badge ${finding.severity.toLowerCase()}`), copy, this.node('span', finding.category, 'finding-category'), this.icon('chevron'));
    row.addEventListener('click', () => this.openFinding(finding)); return row;
  }
  renderFindings() {
    if (!this.report) return;
    const search = this.query('#search').value.toLowerCase(); const severity = this.query('#severity').value; const category = this.query('#category').value;
    const findings = this.report.findings.filter(f => (severity === 'all' || f.severity === severity) && (category === 'all' || f.category === category) && `${f.title} ${f.resource} ${f.category}`.toLowerCase().includes(search));
    this.query('#all-findings').replaceChildren(...findings.map(f => this.findingRow(f)));
    if (!findings.length) this.query('#all-findings').append(this.node('p', 'No findings match these filters.', 'list-empty'));
    this.query('#results-count').textContent = `${findings.length} of ${this.report.findings.length} findings`;
  }
  renderResources() {
    const paths = ['/', '/assets/app.js', '/assets/session.js', '/assets/vendor.js', '/assets/styles.css', '/about', '/login', '/account', '/assets/config.js', '/assets/router.js', '/assets/runtime.js', '/help'];
    this.query('#coverage-total').textContent = '12 sample resources'; this.query('#coverage-note').textContent = 'Synthetic resource inventory. No requests were made to the target.';
    this.query('#resource-list').replaceChildren(...paths.map((path, index) => {
      const row = this.node('div', undefined, 'resource-row'); row.append(this.node('strong', path), this.node('span', 'Sample · checked'), this.node('small', index === 0 || !path.includes('.') ? 'Document' : 'Static asset')); return row;
    }));
  }
  showPage(page) {
    const pages = { overview: ['Audit', 'Website source, headers and TLS.'], findings: ['Findings', 'Review the sample observations and evidence.'], coverage: ['Resources', 'Resources included in the synthetic fixture.'], settings: ['Settings', 'Read-only sample configuration.'] };
    if (!pages[page]) return; this.page = page;
    this.queryAll('.page').forEach(section => { section.hidden = section.id !== `${page}-page`; });
    this.queryAll('.nav-item').forEach(item => { const active = item.dataset.page === page; item.classList.toggle('active', active); if (active) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current'); });
    const title = this.query('#page-title'); title.replaceChildren(document.createTextNode(pages[page][0]), this.node('span', '.'));
    this.query('#page-description').textContent = pages[page][1]; this.query('#breadcrumb').textContent = page === 'overview' ? 'audit' : page === 'coverage' ? 'resources' : page;
    this.scrollTop = 0;
  }
  openFinding(finding) {
    this.query('#detail-severity').textContent = finding.severity; this.query('#detail-severity').className = `badge ${finding.severity.toLowerCase()}`;
    for (const [id, value] of [['detail-title', finding.title], ['detail-category', finding.category], ['detail-evidence', finding.evidence], ['detail-resource', finding.resource], ['detail-remediation', finding.remediation]]) this.query(`#${id}`).textContent = value;
    this.query('#finding-dialog').showModal();
  }
  async setBusy(busy, message) {
    await this.ready; this.busy = busy; this.query('#export-top').disabled = busy; this.query('#new-audit').disabled = busy; this.query('#download-report').disabled = busy;
    this.query('#target-status').textContent = message || (busy ? 'Replaying sample…' : 'Sample complete');
  }
  exportReport() {
    if (!this.report || this.busy) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(this.report, null, 2)], { type: 'application/json' }));
    const anchor = this.node('a'); anchor.href = url; anchor.download = 'gilbrt-demo-report.json'; this.root.append(anchor); anchor.click(); anchor.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    this.dispatchEvent(new CustomEvent('demo-exported', { bubbles: true }));
  }
}
customElements.define('gilbrt-gui-demo', GilbrtGuiDemo);
