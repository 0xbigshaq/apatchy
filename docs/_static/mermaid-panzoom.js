/**
 * Pan & zoom widget for Mermaid SVG diagrams.
 *
 * Waits for Mermaid to render, then wraps each diagram in a container
 * with zoom-in / zoom-out / reset buttons, scroll-wheel zoom, and
 * click-and-drag panning.
 */
(function () {
  "use strict";

  var MIN_SCALE = 0.2;
  var MAX_SCALE = 5;
  var ZOOM_STEP = 0.15;
  var interactive = localStorage.getItem("pz-interactive") !== "false";

  function initPanZoom() {
    var diagrams = document.querySelectorAll(".mermaid-container pre, div.mermaid");
    if (!diagrams.length) return;

    diagrams.forEach(function (container) {
      if (container.dataset.panzoomInit) return;
      container.dataset.panzoomInit = "1";

      var svg = container.querySelector("svg");
      if (!svg) return;

      // Remove sphinxcontrib-mermaid's built-in fullscreen button if present
      var extBtn = container.parentNode &&
        container.parentNode.querySelector(".mermaid-fullscreen-btn");
      if (extBtn) extBtn.remove();

      // -- wrapper structure --
      var wrapper = document.createElement("div");
      wrapper.className = "pz-wrapper";

      var viewport = document.createElement("div");
      viewport.className = "pz-viewport";

      // -- toolbar (above the diagram) --
      var toolbar = document.createElement("div");
      toolbar.className = "pz-toolbar";
      toolbar.innerHTML =
        '<button class="pz-btn pz-toggle' + (interactive ? ' active' : '') + '" data-action="toggle" title="Toggle pan &amp; zoom">' + (interactive ? '&#x1F513;' : '&#x1F512;') + '</button>' +
        '<button class="pz-btn" data-action="in" title="Zoom in">+</button>' +
        '<button class="pz-btn" data-action="out" title="Zoom out">&minus;</button>' +
        '<button class="pz-btn" data-action="reset" title="Reset">&#8634;</button>' +
        '<button class="pz-btn" data-action="fullscreen" title="Fullscreen">&#x26F6;</button>';

      // move SVG into viewport, toolbar first then viewport
      svg.parentNode.insertBefore(wrapper, svg);
      viewport.appendChild(svg);
      wrapper.appendChild(toolbar);
      wrapper.appendChild(viewport);

      // Apply initial cursor based on saved state
      if (!interactive) viewport.style.cursor = "";

      // -- state --
      var scale = 1;
      var panX = 0;
      var panY = 0;
      var dragging = false;
      var startX = 0;
      var startY = 0;
      var startPanX = 0;
      var startPanY = 0;

      function applyTransform() {
        svg.style.transform =
          "translate(" + panX + "px, " + panY + "px) scale(" + scale + ")";
      }

      function clampScale(s) {
        return Math.min(MAX_SCALE, Math.max(MIN_SCALE, s));
      }

      // -- fullscreen overlay --
      var overlay = null;
      var isFullscreen = false;

      function openFullscreen() {
        isFullscreen = true;
        overlay = document.createElement("div");
        overlay.className = "pz-overlay";

        var fsViewport = document.createElement("div");
        fsViewport.className = "pz-fs-viewport";

        var fsToolbar = document.createElement("div");
        fsToolbar.className = "pz-toolbar pz-fs-toolbar";
        fsToolbar.innerHTML =
          '<button class="pz-btn" data-action="in" title="Zoom in">+</button>' +
          '<button class="pz-btn" data-action="out" title="Zoom out">&minus;</button>' +
          '<button class="pz-btn" data-action="reset" title="Reset">&#8634;</button>' +
          '<button class="pz-btn" data-action="close" title="Close">&times;</button>';

        // Clone the SVG so the original stays in place
        var svgClone = svg.cloneNode(true);
        svgClone.style.transform = "";
        svgClone.style.maxWidth = "90vw";
        svgClone.style.maxHeight = "85vh";
        svgClone.style.width = "auto";
        svgClone.style.height = "auto";

        var fsScale = 1;
        var fsPanX = 0;
        var fsPanY = 0;
        var fsDragging = false;
        var fsStartX = 0;
        var fsStartY = 0;
        var fsStartPanX = 0;
        var fsStartPanY = 0;

        function fsApply() {
          svgClone.style.transform =
            "translate(" + fsPanX + "px, " + fsPanY + "px) scale(" + fsScale + ")";
        }

        fsToolbar.addEventListener("click", function (e) {
          var btn = e.target.closest("[data-action]");
          if (!btn) return;
          var a = btn.dataset.action;
          if (a === "in") { fsScale = clampScale(fsScale + ZOOM_STEP); }
          else if (a === "out") { fsScale = clampScale(fsScale - ZOOM_STEP); }
          else if (a === "reset") { fsScale = 1; fsPanX = 0; fsPanY = 0; }
          else if (a === "close") { closeFullscreen(); return; }
          fsApply();
        });

        fsViewport.addEventListener("wheel", function (e) {
          e.preventDefault();
          var d = e.deltaY > 0 ? -ZOOM_STEP : ZOOM_STEP;
          fsScale = clampScale(fsScale + d);
          fsApply();
        }, { passive: false });

        fsViewport.addEventListener("mousedown", function (e) {
          if (e.button !== 0) return;
          fsDragging = true;
          fsStartX = e.clientX;
          fsStartY = e.clientY;
          fsStartPanX = fsPanX;
          fsStartPanY = fsPanY;
          fsViewport.style.cursor = "grabbing";
          e.preventDefault();
        });

        document.addEventListener("mousemove", fsMove);
        document.addEventListener("mouseup", fsUp);

        function fsMove(e) {
          if (!fsDragging) return;
          fsPanX = fsStartPanX + (e.clientX - fsStartX);
          fsPanY = fsStartPanY + (e.clientY - fsStartY);
          fsApply();
        }
        function fsUp() {
          if (!fsDragging) return;
          fsDragging = false;
          fsViewport.style.cursor = "";
        }

        // Close on Escape
        overlay._onKey = function (e) {
          if (e.key === "Escape") closeFullscreen();
        };
        document.addEventListener("keydown", overlay._onKey);

        // Close on backdrop click (overlay or viewport, but not the SVG itself)
        overlay.addEventListener("mousedown", function (e) {
          if (e.target === overlay || e.target === fsViewport) {
            closeFullscreen();
          }
        });

        overlay._fsMove = fsMove;
        overlay._fsUp = fsUp;

        fsViewport.appendChild(svgClone);
        overlay.appendChild(fsViewport);
        overlay.appendChild(fsToolbar);
        document.body.appendChild(overlay);
      }

      function closeFullscreen() {
        if (!overlay) return;
        isFullscreen = false;
        document.removeEventListener("keydown", overlay._onKey);
        document.removeEventListener("mousemove", overlay._fsMove);
        document.removeEventListener("mouseup", overlay._fsUp);
        overlay.remove();
        overlay = null;
      }

      // -- button clicks --
      toolbar.addEventListener("click", function (e) {
        var btn = e.target.closest("[data-action]");
        if (!btn) return;
        var action = btn.dataset.action;
        if (action === "toggle") {
          interactive = !interactive;
          localStorage.setItem("pz-interactive", interactive);
          btn.classList.toggle("active", interactive);
          btn.innerHTML = interactive ? "&#x1F513;" : "&#x1F512;";
          viewport.style.cursor = interactive ? "grab" : "";
          // Sync all other toggle buttons on the page
          document.querySelectorAll('.pz-toggle[data-action="toggle"]').forEach(function (b) {
            if (b === btn) return;
            b.classList.toggle("active", interactive);
            b.innerHTML = interactive ? "&#x1F513;" : "&#x1F512;";
          });
          // Update all viewports
          document.querySelectorAll(".pz-viewport").forEach(function (v) {
            v.style.cursor = interactive ? "grab" : "";
          });
          return;
        } else if (action === "in") {
          scale = clampScale(scale + ZOOM_STEP);
        } else if (action === "out") {
          scale = clampScale(scale - ZOOM_STEP);
        } else if (action === "reset") {
          scale = 1;
          panX = 0;
          panY = 0;
        } else if (action === "fullscreen") {
          openFullscreen();
          return;
        }
        applyTransform();
      });

      // -- scroll wheel zoom --
      viewport.addEventListener("wheel", function (e) {
        if (!interactive) return;
        e.preventDefault();
        var delta = e.deltaY > 0 ? -ZOOM_STEP : ZOOM_STEP;
        scale = clampScale(scale + delta);
        applyTransform();
      }, { passive: false });

      // -- drag to pan --
      viewport.addEventListener("mousedown", function (e) {
        if (!interactive || e.button !== 0) return;
        dragging = true;
        startX = e.clientX;
        startY = e.clientY;
        startPanX = panX;
        startPanY = panY;
        viewport.style.cursor = "grabbing";
        e.preventDefault();
      });

      document.addEventListener("mousemove", function (e) {
        if (!dragging) return;
        panX = startPanX + (e.clientX - startX);
        panY = startPanY + (e.clientY - startY);
        applyTransform();
      });

      document.addEventListener("mouseup", function () {
        if (!dragging) return;
        dragging = false;
        viewport.style.cursor = "";
      });
    });
  }

  // Mermaid renders asynchronously, so wait a bit then init.
  // Also handle pages loaded from cache (DOMContentLoaded already fired).
  function boot() {
    // Retry until diagrams have SVGs (Mermaid may still be rendering)
    var attempts = 0;
    var timer = setInterval(function () {
      attempts++;
      var hasSvg = document.querySelector(".mermaid-container svg, div.mermaid svg");
      if (hasSvg || attempts > 30) {
        clearInterval(timer);
        initPanZoom();
        hideHiddenTabs();
      }
    }, 200);
  }

  // Clean up stale panzoom wrappers so initPanZoom can re-wrap fresh SVGs.
  function cleanupPanZoom() {
    document.querySelectorAll(".pz-wrapper").forEach(function (w) {
      // Unwrap SVG back into its original container before removing the wrapper
      var svg = w.querySelector("svg");
      if (svg && w.parentNode) {
        w.parentNode.insertBefore(svg, w);
      }
      w.remove();
    });
    document.querySelectorAll("[data-panzoom-init]").forEach(function (el) {
      delete el.dataset.panzoomInit;
    });
  }

  // Watch for dark/light mode toggle (sphinx-rtd-dark-mode sets data-theme on <html>).
  // Mermaid may re-render diagrams on theme change, destroying the panzoom wrappers.
  function watchThemeToggle() {
    var observer = new MutationObserver(function (mutations) {
      for (var i = 0; i < mutations.length; i++) {
        if (mutations[i].attributeName === "data-theme") {
          // Hide containers to prevent flash of unstyled full-size SVGs
          var containers = document.querySelectorAll(
            ".mermaid-container, div.mermaid"
          );
          containers.forEach(function (c) { c.style.visibility = "hidden"; });

          showHiddenTabs();
          cleanupPanZoom();
          var attempts = 0;
          var timer = setInterval(function () {
            attempts++;
            var hasSvg = document.querySelector(
              ".mermaid-container svg, div.mermaid svg"
            );
            if (hasSvg || attempts > 30) {
              clearInterval(timer);
              initPanZoom();
              hideHiddenTabs();
              containers.forEach(function (c) { c.style.visibility = ""; });
            }
          }, 200);
          break;
        }
      }
    });
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });
  }

  // Force hidden tab content to render off-screen so mermaid can measure
  // all diagrams (not just those in the active tab). Without this, mermaid
  // computes NaN transforms for diagrams in display:none tabs.
  var preRenderStyle = null;

  function showHiddenTabs() {
    if (preRenderStyle) return;
    preRenderStyle = document.createElement("style");
    preRenderStyle.id = "mermaid-tab-prerender";
    preRenderStyle.textContent =
      ".sd-tab-set > input:not(:checked) + label + .sd-tab-content {" +
      "  display: block !important;" +
      "  position: absolute !important;" +
      "  left: -9999px !important;" +
      "  visibility: hidden !important;" +
      "}";
    document.head.appendChild(preRenderStyle);
  }

  function hideHiddenTabs() {
    if (preRenderStyle) {
      preRenderStyle.remove();
      preRenderStyle = null;
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      showHiddenTabs();
      boot();
      watchThemeToggle();
    });
  } else {
    showHiddenTabs();
    boot();
    watchThemeToggle();
  }
})();


(function() {
  const savedTheme = localStorage.getItem('theme');
  const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  
  // If user saved a preference, use it. Otherwise, use system setting.
  const themeToApply = savedTheme || (systemDark ? 'dark' : 'light');
  
  document.documentElement.setAttribute('data-theme', themeToApply);
})();