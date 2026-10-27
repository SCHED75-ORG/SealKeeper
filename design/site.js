/*
 * SealKeeper website — shared page behaviour.
 *
 * Loaded by every page in design/ as an external script so the
 * Content-Security-Policy in design/_headers can keep script-src to
 * 'self' (no 'unsafe-inline'). Each block is a no-op on pages that do
 * not carry the elements it looks for.
 *
 * Governance pages (body[data-md-source]) also load the self-hosted
 * marked + mermaid bundles from /vendor/ before this file.
 */

// Theme toggle, persisted.
(function () {
  var root = document.documentElement;
  var saved = null;
  try { saved = localStorage.getItem('sk-theme'); } catch (e) {}
  if (saved === 'light' || saved === 'dark') root.setAttribute('data-theme', saved);

  var btn = document.getElementById('theme-toggle');
  if (!btn) return;
  btn.addEventListener('click', function () {
    var systemDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    var current = root.getAttribute('data-theme') || (systemDark ? 'dark' : 'light');
    var next = current === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('sk-theme', next); } catch (e) {}
    btn.setAttribute('aria-pressed', next === 'dark' ? 'true' : 'false');
  });
})();

// Reveal flow steps on scroll
(function () {
  var steps = document.querySelectorAll('.step');
  if (!('IntersectionObserver' in window)) {
    steps.forEach(function (s) { s.classList.add('is-visible'); });
    return;
  }
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (e.isIntersecting) {
        var idx = Array.prototype.indexOf.call(steps, e.target);
        setTimeout(function () { e.target.classList.add('is-visible'); }, Math.min(idx, 8) * 60);
        io.unobserve(e.target);
      }
    });
  }, { threshold: 0.2, rootMargin: '0px 0px -10% 0px' });
  steps.forEach(function (s) { io.observe(s); });
})();

// Copy-to-clipboard for quickstart blocks
(function () {
  document.querySelectorAll('.qs__copy').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var text = btn.getAttribute('data-copy') || '';
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(text).then(function () {
        var prev = btn.textContent;
        btn.textContent = 'Copied';
        btn.setAttribute('aria-pressed', 'true');
        setTimeout(function () {
          btn.textContent = prev;
          btn.setAttribute('aria-pressed', 'false');
        }, 1400);
      });
    });
  });
})();

// Dynamic Markdown + Mermaid loader for governance documents
(async function () {
  var url = document.body.dataset.mdSource;
  if (!url) return;

  var loadingEl = document.getElementById('md-loading');
  var errorEl   = document.getElementById('md-error');
  var contentEl = document.getElementById('md-content');

  // Detect current theme (manual override or system preference)
  function isDarkMode() {
    var theme = document.documentElement.getAttribute('data-theme');
    if (theme === 'dark')  return true;
    if (theme === 'light') return false;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  // Initialise Mermaid with the heraldic palette
  var dark = isDarkMode();
  if (typeof mermaid !== 'undefined') {
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: 'strict',
      theme: 'base',
      themeVariables: {
        darkMode: dark,
        fontFamily: '"Inter", system-ui, sans-serif',
        fontSize: '14px',
        background:        dark ? '#14130F' : '#F4EFE6',
        primaryColor:      '#7A1F2B',
        primaryTextColor:  '#F4EFE6',
        primaryBorderColor:'#C9A961',
        secondaryColor:    '#1E2D45',
        tertiaryColor:     dark ? '#1B1A15' : '#FBF7EE',
        lineColor:         dark ? '#9C988F' : '#7A7670',
        textColor:         dark ? '#F4EFE6' : '#1A1814',
        mainBkg:           '#7A1F2B',
        secondBkg:         '#1E2D45',
        tertiaryBkg:       dark ? '#1B1A15' : '#FBF7EE',
        actorBkg:          '#7A1F2B',
        actorTextColor:    '#F4EFE6',
        actorLineColor:    '#C9A961',
        signalColor:       dark ? '#F4EFE6' : '#1A1814',
        signalTextColor:   dark ? '#F4EFE6' : '#1A1814',
        labelBoxBkgColor:  '#1E2D45',
        labelBoxBorderColor:'#C9A961',
        labelTextColor:    '#F4EFE6',
        loopTextColor:     dark ? '#F4EFE6' : '#1A1814',
        noteBkgColor:      '#C9A961',
        noteTextColor:     '#1A1814',
        noteBorderColor:   '#1A1814',
        activationBkgColor:'#1E2D45',
        activationBorderColor:'#C9A961'
      }
    });
  }

  try {
    var response = await fetch(url, { cache: 'default' });
    if (!response.ok) throw new Error('HTTP ' + response.status);
    var md = await response.text();

    if (typeof marked === 'undefined') throw new Error('marked.js not loaded');

    marked.use({ gfm: true, breaks: false, headerIds: true, mangle: false });
    contentEl.innerHTML = marked.parse(md);

    // Remove the first top-level h1 to avoid duplication with the page-hero title.
    // The markdown source on GitHub keeps its h1 (useful there); the rendered page
    // already has its title in the hero section above.
    var firstH1 = contentEl.querySelector('h1');
    if (firstH1 && firstH1.parentElement === contentEl) {
      firstH1.remove();
    }

    // Convert ```mermaid blocks into <div class="mermaid"> for rendering
    var mermaidBlocks = contentEl.querySelectorAll('pre code.language-mermaid');
    mermaidBlocks.forEach(function (block) {
      var div = document.createElement('div');
      div.className = 'mermaid';
      div.textContent = block.textContent;
      block.parentElement.replaceWith(div);
    });

    // Render mermaid diagrams if any exist
    if (mermaidBlocks.length > 0 && typeof mermaid !== 'undefined') {
      try {
        await mermaid.run({ querySelector: '#md-content .mermaid' });
      } catch (mermaidErr) {
        console.warn('Mermaid render error:', mermaidErr);
      }
    }

    // Rewrite repository-relative links so they resolve on the website:
    // governance documents map to their site page, design/<page>.html to
    // /<page>.html, anything else to its file on GitHub. Absolute URLs
    // (any scheme, protocol-relative) and in-page #anchors are left as is.
    var REPO_BLOB = 'https://github.com/SCHED75-ORG/SealKeeper/blob/main/';
    var SITE_PAGES = {
      'SECURITY.md': '/security.html',
      'CODE_OF_CONDUCT.md': '/code-of-conduct.html',
      'CONTRIBUTING.md': '/contributing.html'
    };
    contentEl.querySelectorAll('a[href]').forEach(function (a) {
      var href = a.getAttribute('href');
      if (!href || /^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i.test(href)) return;
      var hash = '';
      var cut = href.indexOf('#');
      if (cut >= 0) { hash = href.slice(cut); href = href.slice(0, cut); }
      var path = href.replace(/^(?:\.\/)+/, '').replace(/^\/+/, '');
      var page = /^design\/([A-Za-z0-9._-]+\.html)$/.exec(path);
      if (Object.prototype.hasOwnProperty.call(SITE_PAGES, path)) {
        a.setAttribute('href', SITE_PAGES[path] + hash);
      } else if (page) {
        a.setAttribute('href', '/' + page[1] + hash);
      } else {
        a.setAttribute('href', REPO_BLOB + path + hash);
      }
    });

    // Make external links open in a new tab
    contentEl.querySelectorAll('a[href^="http"]').forEach(function (a) {
      a.setAttribute('rel', 'external noopener');
      a.setAttribute('target', '_blank');
    });

    if (loadingEl) loadingEl.remove();
  } catch (err) {
    console.warn('Failed to load Markdown:', err);
    if (loadingEl) loadingEl.remove();
    if (errorEl)   errorEl.style.display = 'block';
  }
})();
