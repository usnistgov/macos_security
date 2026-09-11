// GitHub Latest Release Info Script
// Usage:
//   1. Add <div id="github-latest-release"></div> where you want the info.
//   2. Add <script src="/scripts/github-latest-release.js"></script> to your page.

const GITHUB_OWNER = 'usnistgov';
const GITHUB_REPO = 'macos_security';
const CONTAINER_ID = 'github-latest-release';

// --- Minimal GitHub-flavored Markdown renderer for release notes ---

const REPO_URL_PREFIX = `https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/`;
const KEEP = '\u0000';

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Shorten links back to this repo the way GitHub does: pull/751 -> #751
function linkLabel(url) {
  if (url.indexOf(REPO_URL_PREFIX) === 0) {
    const rest = url.slice(REPO_URL_PREFIX.length);
    const issue = rest.match(/^(?:pull|issues)\/(\d+)$/);
    if (issue) return '#' + issue[1];
    const compare = rest.match(/^compare\/(.+)$/);
    if (compare) return compare[1];
  }
  return url;
}

function anchor(url, label) {
  return `<a href="${url}" target="_blank" rel="noopener">${label}</a>`;
}

function renderInline(text) {
  const kept = [];
  const keep = (html) => KEEP + (kept.push(html) - 1) + KEEP;

  let s = escapeHtml(text);

  // `code` — protected first so nothing below rewrites its contents
  s = s.replace(/`([^`]+)`/g, (_, code) => keep(`<code>${code}</code>`));

  // [label](url) — keep only the tags so the label still picks up bold/italic
  s = s.replace(
    new RegExp('\\[([^\\]' + KEEP + ']+)\\]\\((https?:\\/\\/[^\\s)]+)\\)', 'g'),
    (_, label, url) => keep(`<a href="${url}" target="_blank" rel="noopener">`) + label + keep('</a>')
  );

  // Bare URLs
  s = s.replace(new RegExp('(^|[\\s(])(https?:\\/\\/[^\\s<>()' + KEEP + ']+)', 'g'), (_, before, url) => {
    const trailing = (url.match(/[.,;:!?]+$/) || [''])[0];
    if (trailing) url = url.slice(0, -trailing.length);
    return before + keep(anchor(url, linkLabel(url))) + trailing;
  });

  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/__([^_]+)__/g, '<strong>$1</strong>');
  s = s.replace(/\*([^*\n]+)\*/g, '<em>$1</em>');
  // Underscore italics need word boundaries so snake_case names survive
  s = s.replace(/(^|[\s(])_([^_\n]+)_(?=$|[\s).,;:!?])/g, '$1<em>$2</em>');
  s = s.replace(/~~([^~]+)~~/g, '<del>$1</del>');

  // @mentions, including @dependabot[bot]
  s = s.replace(
    /(^|[^\w\/@])@([A-Za-z\d][A-Za-z\d-]{0,38})(\[bot\])?/g,
    (_, before, user, bot) => before + anchor(`https://github.com/${user}`, '@' + user + (bot || ''))
  );

  return s.replace(new RegExp(KEEP + '(\\d+)' + KEEP, 'g'), (_, i) => kept[i]);
}

function renderMarkdown(md) {
  const lines = String(md).replace(/\r\n?/g, '\n').split('\n');
  const out = [];
  const listStack = [];
  let para = [];
  let quote = [];
  let fence = null;

  const flushPara = () => {
    if (!para.length) return;
    out.push(`<p>${para.map(renderInline).join('<br>')}</p>`);
    para = [];
  };
  const flushQuote = () => {
    if (!quote.length) return;
    out.push(`<blockquote>${renderMarkdown(quote.join('\n'))}</blockquote>`);
    quote = [];
  };
  const closeLists = () => {
    while (listStack.length) out.push(`</li></${listStack.pop().tag}>`);
  };
  const flushBlocks = () => {
    flushPara();
    flushQuote();
    closeLists();
  };

  for (const line of lines) {
    const fenceMark = /^\s*(?:```|~~~)/.test(line);
    if (fence) {
      if (fenceMark) {
        out.push(`<pre><code>${escapeHtml(fence.join('\n'))}</code></pre>`);
        fence = null;
      } else {
        fence.push(line);
      }
      continue;
    }
    if (fenceMark) {
      flushBlocks();
      fence = [];
      continue;
    }

    if (!line.trim()) {
      flushBlocks();
      continue;
    }

    const quoted = line.match(/^\s*>\s?(.*)$/);
    if (quoted) {
      flushPara();
      closeLists();
      quote.push(quoted[1]);
      continue;
    }
    flushQuote();

    const heading = line.match(/^(#{1,6})\s+(.*)$/);
    if (heading) {
      flushBlocks();
      // Offset so a release note's "## Section" sits under the page's own h2
      const level = Math.min(heading[1].length + 2, 6);
      out.push(`<h${level}>${renderInline(heading[2].replace(/\s+#+\s*$/, ''))}</h${level}>`);
      continue;
    }

    if (/^\s*(?:[-*_]\s*){3,}$/.test(line)) {
      flushBlocks();
      out.push('<hr>');
      continue;
    }

    const item = line.match(/^(\s*)(?:([-*+])|(\d+)[.)])\s+(.*)$/);
    if (item) {
      flushPara();
      const indent = item[1].replace(/\t/g, '  ').length;
      const tag = item[2] ? 'ul' : 'ol';
      while (listStack.length && listStack[listStack.length - 1].indent > indent) {
        out.push(`</li></${listStack.pop().tag}>`);
      }
      const top = listStack[listStack.length - 1];
      if (top && top.indent === indent) {
        out.push('</li>');
        if (top.tag !== tag) {
          out.push(`</${listStack.pop().tag}>`);
          out.push(`<${tag}>`);
          listStack.push({ tag, indent });
        }
      } else {
        out.push(`<${tag}>`);
        listStack.push({ tag, indent });
      }
      out.push(`<li>${renderInline(item[4])}`);
      continue;
    }

    // A wrapped line inside a list item, otherwise ordinary paragraph text
    if (listStack.length && /^\s{2,}/.test(line)) {
      out.push(`<br>${renderInline(line.trim())}`);
      continue;
    }
    closeLists();
    para.push(line.trim());
  }

  if (fence) out.push(`<pre><code>${escapeHtml(fence.join('\n'))}</code></pre>`);
  flushBlocks();
  return out.join('');
}

function renderReleaseInfo({ tag_name, name, html_url, published_at, body }) {
  const date = published_at
    ? new Date(published_at).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
    : '';

  let notes = '';
  if (body && body.trim()) {
    notes = `<div class="github-release-notes">${renderMarkdown(body)}</div>`;
  }
  return `
    <div class="github-release-info">
      <div class="github-release-header">
        <svg class="github-release-icon" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 2L2 7l10 5 10-5-10-5z"></path>
          <path d="M2 17l10 5 10-5"></path>
          <path d="M2 12l10 5 10-5"></path>
        </svg>
        <div class="github-release-title-group">
          <a href="${html_url}" target="_blank" rel="noopener" class="github-release-title">
            ${escapeHtml(name || tag_name)}
          </a>
          <span class="github-release-tag">${escapeHtml(tag_name)}</span>
        </div>
      </div>
      ${date ? `<div class="github-release-date">Released: <strong>${date}</strong></div>` : ''}
      ${notes}
      <div class="github-release-links">
        <a href="${html_url}" target="_blank" rel="noopener" class="github-release-btn">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
            <polyline points="7 10 12 15 17 10"></polyline>
            <line x1="12" y1="15" x2="12" y2="3"></line>
          </svg>
          Download
        </a>
        <a href="https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/releases" target="_blank" rel="noopener" class="github-release-link">
          View all releases &rarr;
        </a>
      </div>
    </div>
  `;
}

function showReleaseLoading() {
  const container = document.getElementById(CONTAINER_ID);
  if (container) container.innerHTML = 'Loading latest release...';
}

function showReleaseError() {
  const container = document.getElementById(CONTAINER_ID);
  if (container) container.innerHTML = 'Could not load release info.';
}

function fetchLatestRelease() {
  showReleaseLoading();
  fetch(`https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/releases/latest`)
    .then(res => {
      if (!res.ok) throw new Error('Network response was not ok');
      return res.json();
    })
    .then(release => {
      const container = document.getElementById(CONTAINER_ID);
      if (container) container.innerHTML = renderReleaseInfo(release);
    })
    .catch(() => showReleaseError());
}

function injectReleaseBoxStyles() {
  if (document.getElementById('github-release-style')) return;
  const style = document.createElement('style');
  style.id = 'github-release-style';
  style.textContent = `
    .github-release-info {
      border-radius: 8px;
      padding: 1em 1.25em;
      margin: 1em 0;
      border: 1px solid var(--sl-color-gray-5, #ddd);
      border-left: 3px solid var(--sl-color-accent, #316431);
      background: transparent;
      color: var(--sl-color-text, #333);
      transition: border-color 0.15s ease;
    }
    .github-release-info:hover {
      border-color: var(--sl-color-accent, #316431);
      border-left-color: var(--sl-color-accent, #316431);
    }
    [data-theme="dark"] .github-release-info {
      background: transparent;
      color: var(--sl-color-text, #ccc);
      border-color: var(--sl-color-gray-5, #2a2d35);
      border-left-color: var(--sl-color-accent-high, #6ab549);
    }
    [data-theme="dark"] .github-release-info:hover {
      border-color: var(--sl-color-accent-high, #6ab549);
    }
    .github-release-header {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 0.5rem;
    }
    .github-release-icon {
      color: var(--sl-color-accent, #316431);
      flex-shrink: 0;
      opacity: 0.7;
    }
    [data-theme="dark"] .github-release-icon {
      color: var(--sl-color-accent-high, #6ab549);
      opacity: 0.8;
    }
    .github-release-title-group {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.5rem;
    }
    .github-release-title {
      color: var(--sl-color-text, #111);
      font-size: 1.15em;
      font-weight: 600;
      text-decoration: none;
    }
    .github-release-title:hover {
      text-decoration: underline;
    }
    [data-theme="dark"] .github-release-title {
      color: #fff;
    }
    .github-release-tag {
      background: rgba(0,0,0,0.06);
      color: var(--sl-color-gray-2, #666);
      font-size: 0.75em;
      font-weight: 600;
      padding: 0.2em 0.6em;
      border-radius: 4px;
    }
    [data-theme="dark"] .github-release-tag {
      background: rgba(255,255,255,0.1);
      color: var(--sl-color-gray-2, #aaa);
    }
    .github-release-date {
      font-size: 0.9em;
      color: var(--sl-color-gray-3, #666);
      margin-bottom: 0.5rem;
    }
    [data-theme="dark"] .github-release-date {
      color: var(--sl-color-gray-2, #aaa);
    }
    .github-release-notes {
      margin-top: 0.75em;
      font-size: 0.95em;
      line-height: 1.6;
      color: var(--sl-color-text, #444);
      overflow-wrap: anywhere;
      word-break: break-word;
      padding: 0.75em 1em;
      background: rgba(0,0,0,0.015);
      border-radius: 6px;
      border: 1px solid rgba(0,0,0,0.04);
    }
    [data-theme="dark"] .github-release-notes {
      background: rgba(255,255,255,0.02);
      border-color: rgba(255,255,255,0.05);
    }
    .github-release-notes > :first-child {
      margin-top: 0;
    }
    .github-release-notes > :last-child {
      margin-bottom: 0;
    }
    .github-release-notes :is(h3, h4, h5, h6) {
      margin: 1.25em 0 0.5em;
      font-size: 1em;
      font-weight: 600;
      line-height: 1.3;
      color: var(--sl-color-white, #111);
    }
    .github-release-notes p {
      margin: 0.6em 0;
    }
    .github-release-notes :is(ul, ol) {
      margin: 0.5em 0;
      padding-left: 1.4em;
      list-style-position: outside;
    }
    .github-release-notes ul {
      list-style-type: disc;
    }
    .github-release-notes ol {
      list-style-type: decimal;
    }
    .github-release-notes li {
      margin: 0.2em 0;
    }
    .github-release-notes :is(ul, ol) :is(ul, ol) {
      margin: 0.2em 0;
    }
    .github-release-notes a {
      color: var(--sl-color-accent, #316431);
      text-decoration: none;
    }
    .github-release-notes a:hover {
      text-decoration: underline;
    }
    [data-theme="dark"] .github-release-notes a {
      color: var(--sl-color-accent-high, #6ab549);
    }
    .github-release-notes code {
      font-size: 0.9em;
      padding: 0.15em 0.4em;
      border-radius: 4px;
      background: rgba(0,0,0,0.06);
    }
    [data-theme="dark"] .github-release-notes code {
      background: rgba(255,255,255,0.1);
    }
    .github-release-notes pre {
      margin: 0.6em 0;
      padding: 0.75em;
      overflow-x: auto;
      border-radius: 6px;
      background: rgba(0,0,0,0.05);
    }
    [data-theme="dark"] .github-release-notes pre {
      background: rgba(255,255,255,0.06);
    }
    .github-release-notes pre code {
      padding: 0;
      background: none;
      white-space: pre;
      overflow-wrap: normal;
      word-break: normal;
    }
    .github-release-notes blockquote {
      margin: 0.6em 0;
      padding-left: 0.9em;
      border-left: 3px solid var(--sl-color-gray-5, #ddd);
      color: var(--sl-color-gray-2, #666);
    }
    .github-release-notes hr {
      margin: 1em 0;
      border: 0;
      border-top: 1px solid var(--sl-color-gray-5, #ddd);
    }
    .github-release-links {
      display: flex;
      align-items: center;
      gap: 1rem;
      margin-top: 1rem;
      flex-wrap: wrap;
    }
    .github-release-btn {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      background: var(--sl-color-accent, #316431);
      color: #fff !important;
      padding: 0.5em 1em;
      border-radius: 6px;
      font-size: 0.9em;
      font-weight: 500;
      text-decoration: none !important;
      transition: background 0.2s, transform 0.2s;
    }
    .github-release-btn:hover {
      opacity: 0.9;
      transform: translateY(-1px);
    }
    [data-theme="dark"] .github-release-btn {
      background: var(--sl-color-accent-high, #6ab549);
      color: #111 !important;
    }
    [data-theme="dark"] .github-release-btn:hover {
      opacity: 0.9;
    }
    .github-release-link {
      color: var(--sl-color-accent, #316431);
      font-size: 0.9em;
      text-decoration: none;
    }
    .github-release-link:hover {
      text-decoration: underline;
    }
    [data-theme="dark"] .github-release-link {
      color: var(--sl-color-accent-high, #6ab549);
    }
  `;
  document.head.appendChild(style);
}

// Run immediately if DOM is already loaded, otherwise wait for it
function initRelease() {
  injectReleaseBoxStyles();
  fetchLatestRelease();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initRelease);
} else {
  initRelease();
}
