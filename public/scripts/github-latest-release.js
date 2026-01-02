// GitHub Latest Release Info Script
// Usage:
//   1. Add <div id="github-latest-release"></div> where you want the info.
//   2. Add <script src="/scripts/github-latest-release.js"></script> to your page.

const GITHUB_OWNER = 'usnistgov';
const GITHUB_REPO = 'macos_security';
const CONTAINER_ID = 'github-latest-release';

function renderReleaseInfo({ tag_name, name, html_url, published_at, body }) {
  const date = published_at
    ? new Date(published_at).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
    : '';

  let notes = '';
  if (body) {
    notes = body.replace(/</g, "&lt;");
    notes = notes.replace(
      /\*\*Full Changelog\*\*:\s*(https?:\/\/[^\s]+)/g,
      (match, url) =>
        `<a href="${url}" target="_blank" rel="noopener">Full Changelog</a>`
    );
    notes = `<div class="github-release-notes">${notes}</div>`;
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
            ${name || tag_name}
          </a>
          <span class="github-release-tag">${tag_name}</span>
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
      color: var(--sl-color-text, #444);
      white-space: pre-line;
      overflow-wrap: anywhere;
      word-break: break-word;
      padding: 0.75em;
      background: rgba(0,0,0,0.015);
      border-radius: 6px;
      border: 1px solid rgba(0,0,0,0.04);
    }
    [data-theme="dark"] .github-release-notes {
      background: rgba(255,255,255,0.02);
      border-color: rgba(255,255,255,0.05);
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
