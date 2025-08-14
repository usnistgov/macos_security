// GitHub Star Button Script
// ------------------------------------------------------------
// Dynamically inserts a GitHub "Star" button that adapts to light/dark mode
// and updates automatically when the theme changes. Works with Astro/MDX docs.
//
// Usage:
//   1. Add this to your page where you want the button:
//
//        <div id="github-button-container"></div>
//        <script src="/scripts/github-buttons.js"></script>
//
//   2. The button will automatically update for light/dark mode.
//
// ------------------------------------------------------------


// Returns the GitHub button HTML as a string based on the current theme
function getGitHubButtonHTML() {
  const theme = document.documentElement.getAttribute('data-theme');
  // Only use "light" or "dark" for GitHub Buttons
  const colorScheme = theme === 'dark' ? 'dark' : 'light';
  return `<a
    class="github-button"
    href="https://github.com/usnistgov/macos_security"
    data-size="large"
    data-show-count="true"
    data-color-scheme="${colorScheme}"
    aria-label="Star usnistgov/macos_security on GitHub"
  >Star</a>`;
}

// Insert or update the GitHub button in the container
function renderDynamicGitHubButton(containerId = 'github-button-container') {
  const container = document.getElementById(containerId);
  if (!container) return;
  // Remove any existing button to avoid duplicates
  container.innerHTML = '';
  container.innerHTML = getGitHubButtonHTML();
  // Always try to render after updating the HTML
  if (window.GitHubButtons && typeof window.GitHubButtons.render === 'function') {
    setTimeout(() => {
      window.GitHubButtons.render();
    }, 0);
  }
}

// Helper to ensure GitHubButtons.render is called after the library is loaded
function renderGitHubButtonWhenReady(containerId = 'github-button-container') {
  renderDynamicGitHubButton(containerId);
  // Remove the retry loop, since renderDynamicGitHubButton already calls render if available
}

// Optionally, insert the button into a container and load the library if needed
function insertGitHubButton(containerId = 'github-button-container') {
  // Remove any existing GitHub Buttons script to force re-processing
  const existingScript = document.querySelector('script[src="https://buttons.github.io/buttons.js"]');
  if (existingScript) {
    existingScript.remove();
    window._githubButtonsLoaded = false;
  }
  // Only render after the library is loaded
  if (!window._githubButtonsLoaded) {
    var script = document.createElement('script');
    script.async = true;
    script.defer = true;
    script.src = 'https://buttons.github.io/buttons.js';
    script.onload = () => {
      window._githubButtonsLoaded = true;
      renderDynamicGitHubButton(containerId);
    };
    document.body.appendChild(script);
  } else {
    renderDynamicGitHubButton(containerId);
  }
}

// Export for manual use
window.getGitHubButtonHTML = getGitHubButtonHTML;
window.insertGitHubButton = insertGitHubButton;

// Listen for theme changes via MutationObserver
const observer = new MutationObserver(() => {
  insertGitHubButton(); // Use insertGitHubButton to ensure script is loaded
});
observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

// Still listen for custom themechange event for compatibility
document.addEventListener('themechange', () => {
  insertGitHubButton(); // Use insertGitHubButton to ensure script is loaded
});

window.addEventListener('DOMContentLoaded', () => {
  insertGitHubButton();
});

