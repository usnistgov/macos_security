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
    notes = `<div class="github-release-notes" style="margin-top:1em; font-size:0.98em; color:var(--sl-color-text, #444); white-space:pre-line;">${notes}</div>`;
  }
  return `
    <div class="github-release-info">
      <strong><a href="${html_url}" target="_blank" rel="noopener">
        ${name || tag_name}
      </a></strong>
      <span style="color: #888; font-size: 0.9em; font-style: italic;">(${tag_name})</span>
      ${date ? `<div style="font-size:0.9em; color:var(--sl-color-text, #666); margin-top:2px;">Released: <strong>${date}</strong></div>` : ''}
      ${notes}
      <div style="margin-top:0.7em;">
        <a href="https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/releases" target="_blank" rel="noopener" style="font-size:0.95em;">
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
      border-radius: 12px;
      padding: 1.25em 1.5em;
      margin: 1.5em 0;
      border: 1px solid #cbd3d8ff;
      background: var(--sl-color-bg, #fff);
      color: var(--sl-color-text, #316431);
      box-shadow: 0 2px 8px 0 rgba(60,60,60,0.06);
      transition: background 0.2s, color 0.2s, border-color 0.2s;
    }
    [data-theme="dark"] .github-release-info {
      background: var(--sl-color-bg, #161b22);
      color: var(--sl-color-text, #6ab549);
      border-color: #2d3133ff;
      box-shadow: 0 2px 8px 0 rgba(0,0,0,0.10);
    }
    .github-release-info a {
      color: var(--sl-color-accent, #316431);
      text-decoration: none;
      font-weight: 500;
      transition: color 0.2s;
    }
    [data-theme="dark"] .github-release-info a {
      color: var(--sl-color-accent-high, #6ab549);
    }
    .github-release-info a:hover {
      text-decoration: underline;
    }
    .github-release-info span {
      color: #888;
      font-size: 0.9em;
    }
    [data-theme="dark"] .github-release-info span {
      color: #aaa;
    }
    .github-release-info strong {
      color: #111;
      font-size: 1.08em;
    }
    [data-theme="dark"] .github-release-info strong {
      color: #fff;
    }
  `;
  document.head.appendChild(style);
}

window.addEventListener('DOMContentLoaded', () => {
  injectReleaseBoxStyles();
  fetchLatestRelease();
});
