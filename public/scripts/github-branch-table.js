// GitHub Branch Version Table Script
// Shows macOS version branches with their last update date

const GITHUB_OWNER = 'usnistgov';
const GITHUB_REPO = 'macos_security';
const BRANCH_CONTAINER_ID = 'github-branch-table';

// Define the branches with their macOS version info
const BRANCHES = [
  { name: 'tahoe', macOS: 'macOS 26 (Tahoe)', current: true },
  { name: 'sequoia', macOS: 'macOS 15 (Sequoia)', current: false },
  { name: 'sonoma', macOS: 'macOS 14 (Sonoma)', current: false },
  { name: 'dev_2.0', macOS: 'mSCP 2.0 (Beta)', current: false, beta: true },
];

function fetchBranchInfo(branchName) {
  return fetch('https://api.github.com/repos/' + GITHUB_OWNER + '/' + GITHUB_REPO + '/branches/' + branchName)
    .then(function(res) {
      if (!res.ok) return null;
      return res.json();
    })
    .then(function(data) {
      if (!data) return null;
      var commitDate = data.commit && data.commit.commit && data.commit.commit.author && data.commit.commit.author.date;
      var sha = data.commit && data.commit.sha ? data.commit.sha.substring(0, 7) : null;
      return {
        lastCommit: commitDate,
        sha: sha
      };
    })
    .catch(function() {
      return null;
    });
}

function formatDate(dateString) {
  if (!dateString) return 'N/A';
  return new Date(dateString).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
}

function renderBranchTable(branchData) {
  var rows = branchData.map(function(branch) {
    var badge = '';
    if (branch.current) {
      badge = '<span class="branch-current-badge">Current</span>';
    } else if (branch.beta) {
      badge = '<span class="branch-beta-badge">Beta</span>';
    }
    var dateDisplay = branch.info
      ? formatDate(branch.info.lastCommit)
      : '<span class="branch-loading">Loading...</span>';

    return '<tr>' +
      '<td>' +
        '<a href="https://github.com/' + GITHUB_OWNER + '/' + GITHUB_REPO + '/tree/' + branch.name + '" target="_blank" rel="noopener" class="branch-link">' +
          branch.name +
        '</a>' +
        badge +
      '</td>' +
      '<td>' + branch.macOS + '</td>' +
      '<td class="branch-date">' + dateDisplay + '</td>' +
      '<td>' +
        '<a href="https://github.com/' + GITHUB_OWNER + '/' + GITHUB_REPO + '/commits/' + branch.name + '" target="_blank" rel="noopener" class="branch-commits-link">' +
          'View commits &rarr;' +
        '</a>' +
      '</td>' +
    '</tr>';
  }).join('');

  return '<div class="github-branch-table-wrapper">' +
    '<table class="github-branch-table">' +
      '<thead>' +
        '<tr>' +
          '<th>Branch</th>' +
          '<th>macOS Version</th>' +
          '<th>Last Updated</th>' +
          '<th>History</th>' +
        '</tr>' +
      '</thead>' +
      '<tbody>' +
        rows +
      '</tbody>' +
    '</table>' +
  '</div>';
}

function loadBranchTable() {
  const container = document.getElementById(BRANCH_CONTAINER_ID);
  if (!container) {
    console.error('Branch table container not found');
    return;
  }

  // Initial render with loading state
  const initialData = BRANCHES.map(function(b) { return Object.assign({}, b, { info: null }); });
  container.innerHTML = renderBranchTable(initialData);

  // Fetch all branch info in parallel
  var promises = BRANCHES.map(function(branch) {
    return fetchBranchInfo(branch.name).then(function(info) {
      return Object.assign({}, branch, { info: info });
    });
  });

  Promise.all(promises).then(function(branchData) {
    container.innerHTML = renderBranchTable(branchData);
  }).catch(function(err) {
    console.error('Error loading branch data:', err);
  });
}

function injectBranchTableStyles() {
  if (document.getElementById('github-branch-table-style')) return;
  const style = document.createElement('style');
  style.id = 'github-branch-table-style';
  style.textContent = `
    .github-branch-table-wrapper {
      margin: 1em 0;
      border-radius: 12px;
      overflow: hidden;
      border: 1px solid var(--sl-color-gray-5, #ddd);
    }
    [data-theme="dark"] .github-branch-table-wrapper {
      border-color: var(--sl-color-gray-5, #333);
    }
    .github-branch-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.95em;
    }
    .github-branch-table thead {
      background: var(--sl-color-accent-low, #e8f5e9);
    }
    [data-theme="dark"] .github-branch-table thead {
      background: rgba(49, 100, 49, 0.2);
    }
    .github-branch-table th {
      text-align: left;
      padding: 0.75em 1em;
      font-weight: 600;
      color: var(--sl-color-text, #333);
      border-bottom: 2px solid var(--sl-color-accent, #316431);
    }
    [data-theme="dark"] .github-branch-table th {
      color: var(--sl-color-white, #fff);
    }
    .github-branch-table td {
      padding: 0.7em 1em;
      border-bottom: 1px solid var(--sl-color-gray-6, #eee);
      vertical-align: middle;
    }
    [data-theme="dark"] .github-branch-table td {
      border-bottom-color: var(--sl-color-gray-5, #333);
    }
    .github-branch-table tbody tr:last-child td {
      border-bottom: none;
    }
    .github-branch-table tbody tr:hover {
      background: var(--sl-color-gray-7, #f9f9f9);
    }
    [data-theme="dark"] .github-branch-table tbody tr:hover {
      background: rgba(255,255,255,0.03);
    }
    .branch-link {
      color: var(--sl-color-accent, #316431);
      font-weight: 600;
      text-decoration: none;
    }
    .branch-link:hover {
      text-decoration: underline;
    }
    [data-theme="dark"] .branch-link {
      color: var(--sl-color-accent-high, #6ab549);
    }
    .branch-current-badge {
      display: inline-block;
      background: var(--sl-color-green, #316431);
      color: #fff;
      font-size: 0.7em;
      font-weight: 600;
      padding: 0.15em 0.5em;
      border-radius: 4px;
      margin-left: 0.5em;
      vertical-align: middle;
    }
    [data-theme="dark"] .branch-current-badge {
      background: var(--sl-color-green-high, #6ab549);
      color: #111;
    }
    .branch-beta-badge {
      display: inline-block;
      background: var(--sl-color-orange, #f5a623);
      color: #111;
      font-size: 0.7em;
      font-weight: 600;
      padding: 0.15em 0.5em;
      border-radius: 4px;
      margin-left: 0.5em;
      vertical-align: middle;
    }
    [data-theme="dark"] .branch-beta-badge {
      background: var(--sl-color-orange-high, #ffc670);
      color: #111;
    }
    .branch-date {
      color: var(--sl-color-gray-2, #666);
    }
    [data-theme="dark"] .branch-date {
      color: var(--sl-color-gray-3, #aaa);
    }
    .branch-commits-link {
      color: var(--sl-color-gray-2, #666);
      font-size: 0.9em;
      text-decoration: none;
    }
    .branch-commits-link:hover {
      color: var(--sl-color-accent, #316431);
      text-decoration: underline;
    }
    [data-theme="dark"] .branch-commits-link {
      color: var(--sl-color-gray-3, #aaa);
    }
    [data-theme="dark"] .branch-commits-link:hover {
      color: var(--sl-color-accent-high, #6ab549);
    }
    .branch-loading {
      color: var(--sl-color-gray-3, #999);
      font-style: italic;
    }
    @media (max-width: 600px) {
      .github-branch-table th,
      .github-branch-table td {
        padding: 0.5em 0.6em;
        font-size: 0.9em;
      }
      .github-branch-table th:nth-child(4),
      .github-branch-table td:nth-child(4) {
        display: none;
      }
    }
  `;
  document.head.appendChild(style);
}

// Run immediately if DOM is already loaded, otherwise wait for it
function init() {
  console.log('Branch table script initializing...');
  injectBranchTableStyles();
  loadBranchTable();
  console.log('Branch table script initialized');
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
