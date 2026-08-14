/* TableX front-end glue. Deliberately small and CSP-safe: no inline scripts, no
 * eval. Alpine is the @alpinejs/csp build, so components are registered via
 * Alpine.data() and templates reference properties/methods by name only. */
(function () {
  "use strict";

  /* --- Align htmx with the strict CSP (script-src 'self'; no unsafe-eval /
   *     unsafe-inline). The vendored htmx defaults to allowEval/allowScriptTags
   *     true, so it would attempt eval-based features (hx-trigger filters, js:/
   *     hx-on expressions) and <script>-in-swap execution that the browser then
   *     blocks via CSP — console violations with no graceful degrade. Turn them
   *     off so htmx never tries. htmx loads first (deferred, before this script),
   *     so window.htmx exists here; selfRequestsOnly stays at its safe 2.0
   *     default (true). --- */
  if (window.htmx && window.htmx.config) {
    window.htmx.config.allowEval = false;
    window.htmx.config.allowScriptTags = false;
    /* htmx keeps up to 10 rendered pages in sessionStorage for back/forward.
     * In an admin tool those pages ARE the data — query results, table contents,
     * user lists — so the default leaves rows from a database on disk in the
     * browser profile, outliving the session that fetched them. Zero means
     * back/forward re-requests the page instead, which costs a round trip and
     * gains fresh rows and nothing at rest. */
    window.htmx.config.historyCacheSize = 0;
  }

  /* Elements whose pending request htmx really is going to prompt for. Written
     by the htmx:confirm handler below — the only place the question is visible —
     and consumed by configRequest. A WeakMap so an element removed by a swap
     cannot pin anything. */
  var confirmed = new WeakMap();

  /* --- CSRF: attach the per-session token to every htmx request --- */
  document.addEventListener("htmx:configRequest", function (e) {
    var m = document.querySelector('meta[name="csrf-token"]');
    if (m && m.content) {
      e.detail.headers["X-CSRF-Token"] = m.content;
    }
    /* Destructive actions are gated server-side: without a confirmation field
       the handler answers with an interstitial page instead of acting, so a
       Drop button works safely with JavaScript disabled. This event only fires
       for a request htmx is actually issuing, so a recorded question means the
       user accepted it — add the field and the JS path stays one round trip
       with one prompt rather than a dialog followed by a page.
       The answer is NOT derivable here: this event's detail carries no
       confirmation data at all. Hence the handoff. What it replaces was a
       closest-ancestor test for the hx-confirm ATTRIBUTE, wrong twice over —
       the attribute is INHERITED, so a descendant that never showed a dialog
       matched a parent's; and the value "unset", the documented way to CANCEL
       an inherited one, still IS that attribute, so the links using it matched
       too. */
    var el = e.detail.elt;
    if (el && confirmed.get(el)) {
      confirmed.delete(el); /* one-shot: the next request must earn it again */
      e.detail.parameters["tx_confirm"] = "1";
    }
  });

  /* --- Unsaved changes ----------------------------------------------------- *
   * Nothing protected typed-in work. Clicking a table in the tree mid-edit threw
   * away a written query, a filled row, or a half-defined table — and because
   * htmx swaps instead of navigating, the browser never got the chance to ask.
   *
   * A form opts in with data-tx-guard="<what would be lost>", so the question can
   * name the thing rather than say "changes". Only forms where the work is
   * genuinely expensive to retype carry it; guarding every form in the app would
   * mean prompting over a rows-per-page dropdown, and a prompt that fires when
   * nothing is at stake is one people learn to dismiss unread.
   *
   * Dirtiness is a class ON the form, which means it needs no cleanup: the swap
   * that replaces the form takes the flag with it. */
  var GUARDED = "[data-tx-guard]";

  function markDirty(el) {
    var form = el && el.closest ? el.closest(GUARDED) : null;
    if (form) form.classList.add("tx-dirty");
  }
  function dirtyForm() {
    return document.querySelector(GUARDED + ".tx-dirty");
  }
  document.addEventListener("input", function (e) {
    markDirty(e.target);
  });
  document.addEventListener("change", function (e) {
    markDirty(e.target);
  });

  /* Real navigations — a typed URL, a closed tab, a non-htmx link. The browser
     shows its own wording; returnValue is set because older engines require it. */
  window.addEventListener("beforeunload", function (e) {
    if (!dirtyForm()) return;
    e.preventDefault();
    e.returnValue = "";
  });

  /* htmx navigations, which never unload the page. htmx fires this before every
     request; cancelling it means the request is ours to issue.
     issueRequest() is called with no argument on purpose: that re-enters with
     skipConfirm=false, so an element that also carries hx-confirm still gets its
     own dialog. Passing true would skip it — and since configRequest adds the
     server-side tx_confirm field to anything carrying hx-confirm, that would turn
     a confirmed destructive action into an unconfirmed one. */
  document.addEventListener("htmx:confirm", function (e) {
    /* Record whether htmx is about to prompt, BEFORE the dirtyForm() return
       below. detail.question is set only when an hx-confirm value resolved for
       this element — "unset" resolves to nothing, which is how cancelling an
       inherited attribute works — and it is documented as available only when
       the attribute is present, so this is the one place the answer exists.
       Placed AFTER that return, a page with no dirty form would record nothing,
       configRequest would stop sending tx_confirm, and every confirmed
       destructive action would turn into a server interstitial. */
    var elt = e.detail.elt;
    if (elt) {
      if (e.detail.question) {
        confirmed.set(elt, true);
      } else {
        confirmed.delete(elt); /* never leave a stale entry to be read later */
      }
    }
    var form = dirtyForm();
    if (!form) return;
    if (elt && (elt === form || form.contains(elt))) return; // this IS the save
    /* Only a swap of the main region discards the form. Expanding the nav tree
       targets the tree and leaves the form alone. */
    var target = e.detail.target;
    if (!target || target.id !== "page_content") return;

    e.preventDefault();
    var what = form.getAttribute("data-tx-guard") || "your unsaved changes";
    if (confirm("Leave this page and discard " + what + "?")) {
      e.detail.issueRequest();
    }
  });

  /* --- Announcements ------------------------------------------------------- *
   * #tx-announce is a permanent aria-live region in the shell. It exists because
   * a role="alert" element that is CREATED by a swap is announced unreliably —
   * several screen readers only watch regions that were present when they built
   * their model of the page. So the region is always there and the text is moved
   * into it.
   *
   * The clear-then-set is not superstition: setting the same string twice in a
   * row is not a change, and an unchanged region is not announced. Two saves in
   * a row both reporting "1 row affected" would otherwise be silent the second
   * time. */
  function announce(msg) {
    var region = document.getElementById("tx-announce");
    if (!region || !msg) return;
    region.textContent = "";
    setTimeout(function () {
      region.textContent = msg;
    }, 60);
  }

  /* --- htmx error feedback: failures must never be silent no-ops --- */
  function showToast(msg) {
    var box = document.getElementById("tx-toast-box");
    if (!box) {
      box = document.createElement("div");
      box.id = "tx-toast-box";
      document.body.appendChild(box);
    }
    var t = document.createElement("div");
    t.className = "tx-toast";
    t.setAttribute("role", "alert");
    t.textContent = msg;
    box.appendChild(t);
    announce(msg);
    setTimeout(function () {
      t.remove();
    }, 6000);
  }
  document.addEventListener("htmx:responseError", function (e) {
    var xhr = e.detail.xhr;
    // A 401 carries HX-Redirect (expired session): htmx already navigates to
    // the login page for any response bearing that header — say nothing here.
    if (xhr.status === 401 || xhr.getResponseHeader("HX-Redirect")) return;
    if (xhr.status === 403) {
      showToast("Request rejected (security token expired or invalid). Reload the page and try again.");
      return;
    }
    showToast("Request failed (" + xhr.status + " " + (xhr.statusText || "error") + ").");
  });
  document.addEventListener("htmx:sendError", function () {
    showToast("Network error: the server could not be reached. Check the connection and try again.");
  });

  /* --- Loading feedback ---------------------------------------------------- *
   * Nothing in TableX is instant: a navigation runs introspection, a browse can
   * run COUNT(*), a console submit can run anything at all. Without an
   * acknowledgement the click looks ignored and the user clicks again, which on
   * a POST means running it twice.
   *
   * Three signals, all from the same pair of events:
   *   - a progress bar across the top, driven by a count of in-flight requests
   *     so two overlapping requests cannot end it early;
   *   - aria-busy on the region being replaced, which dims it (CSS) and tells
   *     assistive tech the content is stale;
   *   - the submit controls of the submitting form go disabled, so the second
   *     click has nothing to hit.
   *
   * htmx has hx-disabled-elt for that last part, but it logs a console warning
   * whenever its selector matches nothing — which every non-form request would
   * do — so the rule lives here once rather than on every form in the app.
   *
   * The pairing is safe: htmx fires afterRequest from onload, onerror AND
   * onabort, so the counter cannot leak on a failure. It would leak if a
   * listener cancelled htmx:beforeRequest, which nothing here does. */
  var inflight = 0;
  var progressSeq = 0;

  function progressBar() {
    return document.getElementById("tx-progress");
  }
  function progressStart() {
    var el = progressBar();
    if (!el) return;
    progressSeq++; // invalidate a pending cleanup from the previous request
    el.classList.remove("is-done");
    /* Read a layout property so the browser commits width:0 before is-loading
       animates away from it; without this the bar resumes from wherever the
       last one stopped. */
    void el.offsetWidth;
    el.classList.add("is-loading");
  }
  function progressDone() {
    var el = progressBar();
    if (!el) return;
    var mine = ++progressSeq;
    el.classList.remove("is-loading");
    el.classList.add("is-done");
    setTimeout(function () {
      /* Only clean up if no request started in the meantime. */
      if (mine === progressSeq) el.classList.remove("is-done");
    }, 500);
  }

  /* The submit controls of the form that issued this request, if it was a form.
     A <button> with no type is a submit button; type="button" is not. */
  function submitControls(elt) {
    if (!elt || !elt.closest) return null;
    var form = elt.tagName === "FORM" ? elt : elt.closest("form");
    if (!form) return null;
    return form.querySelectorAll(
      'button[type="submit"], button:not([type]), input[type="submit"]'
    );
  }

  document.addEventListener("htmx:beforeRequest", function (e) {
    inflight++;
    if (inflight === 1) progressStart();

    var target = e.detail.target;
    if (target && target.setAttribute) target.setAttribute("aria-busy", "true");

    var controls = submitControls(e.detail.elt);
    if (!controls) return;
    /* Remember only what we disabled: a control already disabled (restricted
       mode, an empty selection) must stay that way when the request ends. */
    var locked = [];
    for (var i = 0; i < controls.length; i++) {
      if (!controls[i].disabled) {
        controls[i].disabled = true;
        locked.push(controls[i]);
      }
    }
    e.detail.elt.txLocked = locked;
  });

  document.addEventListener("htmx:afterRequest", function (e) {
    inflight = Math.max(0, inflight - 1);
    if (inflight === 0) progressDone();

    var target = e.detail.target;
    if (target && target.removeAttribute) target.removeAttribute("aria-busy");

    var elt = e.detail.elt;
    if (elt && elt.txLocked) {
      for (var i = 0; i < elt.txLocked.length; i++) elt.txLocked[i].disabled = false;
      elt.txLocked = null;
    }
  });

  /* A structural change (create/drop a database, create/drop/rename a table) sends
   * HX-Trigger: tx-nav-refresh; re-fetch the top-level tree so the sidebar
   * (which lives outside the swapped #page_content) stays in sync. */
  document.body.addEventListener("tx-nav-refresh", function () {
    if (window.htmx) {
      window.htmx.ajax("GET", "/nav", { target: "#tx_nav_tree" });
    }
  });

  /* --- Navigation tree: clicking a link must navigate (htmx) without toggling
   *     the enclosing <details> disclosure. --- */
  document.addEventListener("click", function (e) {
    var link = e.target.closest(".tx-tree-link");
    if (link && link.closest("summary")) {
      e.preventDefault(); // suppress the native <details> toggle; htmx navigates
    }
  });

  /* --- Fast filter for the database tree ---------------------------------- *
   * Two fixes over the original: it matched database names only, so filtering an
   * expanded database hid nothing inside it; and it wrote inline display styles
   * that any tree refresh threw away, leaving the box still holding text while
   * the whole tree came back — the filter appeared to clear itself. Extracted
   * into a function so the swap can re-apply it. */
  function applyNavFilter() {
    var input = document.getElementById("tx-nav-filter-input");
    var tree = document.getElementById("tx_nav_tree");
    if (!input || !tree) return;
    var q = input.value.trim().toLowerCase();
    tree.querySelectorAll(".tx-node-database").forEach(function (li) {
      var dbHit =
        !q || (li.getAttribute("data-name") || "").toLowerCase().indexOf(q) !== -1;
      /* Children exist in the DOM only once the database has been expanded.
         Where they do, a match on a table keeps its database visible — hiding
         the parent of a match would be worse than not matching at all. */
      var kidHit = false;
      li.querySelectorAll(".tx-node-table, .tx-node-view").forEach(function (k) {
        var self =
          !q || (k.getAttribute("data-name") || "").toLowerCase().indexOf(q) !== -1;
        k.style.display = dbHit || self ? "" : "none";
        if (self && q) kidHit = true;
      });
      li.style.display = dbHit || kidHit ? "" : "none";
    });
  }

  document.addEventListener("input", function (e) {
    if (e.target && e.target.id === "tx-nav-filter-input") {
      applyNavFilter();
    }
  });

  /* --- Browse: the classic "selected row" highlight ---
   * Checking a row's box marks its <tr> (.tx-marked → peach background); the
   * check-all box marks every row in its form. Delegated so it survives htmx
   * swaps with no template edits or inline handlers (CSP-safe). Alpine sets the
   * sibling checkboxes' .checked programmatically (which fires no change event),
   * so the check-all branch syncs the rows itself. */
  document.addEventListener("change", function (e) {
    var t = e.target;
    if (!t || !t.classList) return;
    if (t.classList.contains("tx-check")) {
      var row = t.closest("tr");
      if (row) row.classList.toggle("tx-marked", t.checked);
    } else if (t.classList.contains("tx-check-all")) {
      var form = t.closest(".tx-browse-form");
      if (!form) return;
      var on = t.checked;
      form.querySelectorAll(".tx-check").forEach(function (c) {
        var r = c.closest("tr");
        if (r) r.classList.toggle("tx-marked", on);
      });
    }
  });

  /* --- Nav tree: keep the active node in sync after htmx navigations ---
   * The tree DOM persists across #page_content swaps, so the server-rendered
   * .active marker goes stale. After each swap re-mark the node whose link
   * matches the current URL and open its ancestor disclosures. */
  // The active node is matched by path PREFIX plus ONLY the normalized schema
  // query param. PostgreSQL schemas differ solely by ?schema=, so comparing
  // pathname alone would highlight the wrong same-named table across schemas;
  // the other query params (browse URLs add order/dir/rows/pos) are ignored so
  // the highlight survives a sort or pagination. schema is the only param a
  // nav-tree link itself carries.
  function markActiveNavNode() {
    var tree = document.getElementById("tx_nav_tree");
    if (!tree) return;
    tree.querySelectorAll(".active").forEach(function (el) {
      el.classList.remove("active");
    });
    // Longest path-PREFIX match, not exact: a nav link's href omits the
    // default tab segment (urls.go: a database node is /db/{db}, a table node
    // /db/{db}/table/{t}), so a sub-tab URL like /db/{db}/table/{t}/structure
    // or /db/{db}/sql shares no exact key with any node but IS prefixed by
    // one. Three rules keep it correct: the schema component must still match
    // exactly (a database node and its schema node share a pathname and differ
    // only by ?schema); the boundary check stops /db/foo matching /db/foobar;
    // and longest-prefix wins, so a table node beats its parent database node,
    // whose href is also a prefix.
    var wantLoc = window.location;
    var wantSchema = new URLSearchParams(wantLoc.search).get("schema") || "";
    var wantPath = wantLoc.pathname;
    var links = tree.querySelectorAll("a.tx-tree-link");
    var match = null;
    var bestLen = -1;
    for (var i = 0; i < links.length; i++) {
      var linkSchema = new URLSearchParams(links[i].search).get("schema") || "";
      if (linkSchema !== wantSchema) continue;
      var p = links[i].pathname;
      if (wantPath !== p && wantPath.indexOf(p) !== 0) continue;
      // Prefix must land on a path-segment boundary: the whole path, or the
      // next character is '/'.
      if (wantPath.length > p.length && wantPath.charAt(p.length) !== "/") continue;
      if (p.length > bestLen) {
        bestLen = p.length;
        match = links[i];
      }
    }
    if (!match) return;
    var node = match.closest(".tx-tree-node");
    if (node) node.classList.add("active");
    var row = match.closest(".tx-tree-row");
    if (row) row.classList.add("active");
    for (
      var d = match.closest("details");
      d;
      d = d.parentElement && d.parentElement.closest("details")
    ) {
      d.open = true;
    }
  }

  /* --- Color mode toggle (modernization, opt-in, defaults to light) ---
   * The choice is mirrored to a cookie so the server can render the correct
   * data-bs-theme on the first paint (no flash of the wrong theme on reload). */
  function applyTheme(t) {
    document.documentElement.setAttribute("data-bs-theme", t);
  }
  function secureFlag() {
    return window.location.protocol === "https:" ? ";Secure" : "";
  }
  function persistTheme(t) {
    try {
      localStorage.setItem("tx-theme", t);
    } catch (_) {}
    document.cookie =
      "tx-theme=" + t + ";path=/;max-age=31536000;SameSite=Lax" + secureFlag();
  }
  /* Does the OS ask for dark? Used only while the user has made no choice of
     their own, so an explicit toggle always wins over the system setting. */
  function prefersDark() {
    return !!(window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
  }
  function chosenTheme() {
    try {
      var saved = localStorage.getItem("tx-theme");
      // Whitelist before applying: only the two known modes are valid, matching
      // the server-side themeFromRequest guard. Anything else is ignored.
      return saved === "dark" || saved === "light" ? saved : null;
    } catch (_) {
      return null;
    }
  }
  var chosen = chosenTheme();
  if (chosen) {
    applyTheme(chosen);
    persistTheme(chosen); // sync the cookie for server-side rendering
  } else if (prefersDark()) {
    /* A first visit used to render light regardless of the system setting.
       The cookie is written so the SERVER paints dark on the next full load
       (otherwise every reload flashes light first), but localStorage is left
       alone: that is the record of a deliberate choice, and the OS preference
       is not one. */
    applyTheme("dark");
    document.cookie =
      "tx-theme=dark;path=/;max-age=31536000;SameSite=Lax" + secureFlag();
  }
  /* Follow the OS while the user still has no preference of their own. */
  if (!chosen && window.matchMedia) {
    var mq = window.matchMedia("(prefers-color-scheme: dark)");
    var onSchemeChange = function () {
      if (chosenTheme()) return;
      var t = mq.matches ? "dark" : "light";
      applyTheme(t);
      document.cookie =
        "tx-theme=" + t + ";path=/;max-age=31536000;SameSite=Lax" + secureFlag();
    };
    if (mq.addEventListener) mq.addEventListener("change", onSchemeChange);
  }
  document.addEventListener("click", function (e) {
    if (e.target.closest("[data-tx-theme-toggle]")) {
      var cur = document.documentElement.getAttribute("data-bs-theme") || "light";
      var next = cur === "dark" ? "light" : "dark";
      applyTheme(next);
      persistTheme(next);
    }
  });

  /* --- Mobile navigation drawer (off-canvas below 768px) ------------------- *
   * The drawer is hidden by CSS (visibility, so it leaves the tab order — see
   * .tx-nav in the max-width block). What CSS cannot do is the rest of the modal
   * contract: while an overlay drawer is open, focus belongs inside it and must
   * come back to the control that opened it. Both are done here, and both are
   * conditional on the drawer actually being an overlay: on a wide screen the
   * sidebar is permanent furniture and trapping focus in it would be a bug. */
  var navReturnFocus = null;

  function navIsOverlay() {
    /* The same 767.98px breakpoint the stylesheet uses. Read from the toggle's
       computed display rather than duplicating the number: the button is shown
       only in the drawer layout, so if it is visible, the drawer is an overlay. */
    var btn = document.querySelector("[data-tx-nav-toggle]");
    return !!btn && getComputedStyle(btn).display !== "none";
  }

  function focusables(root) {
    return Array.prototype.filter.call(
      root.querySelectorAll(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]),' +
          ' textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])'
      ),
      function (el) {
        /* offsetParent is null for anything display:none — a collapsed <details>
           hides its children that way, and they must not be trapped into. */
        return el.offsetParent !== null;
      }
    );
  }

  function setNavOpen(open, restoreFocus) {
    var wasOpen = document.body.classList.contains("tx-nav-open");
    document.body.classList.toggle("tx-nav-open", open);
    var btn = document.querySelector("[data-tx-nav-toggle]");
    if (btn) btn.setAttribute("aria-expanded", open ? "true" : "false");
    if (!navIsOverlay()) return;

    if (open && !wasOpen) {
      navReturnFocus = document.activeElement;
      var nav = document.getElementById("tx_nav");
      var first = nav && focusables(nav)[0];
      if (first) first.focus();
    } else if (!open && wasOpen && restoreFocus !== false) {
      /* Only when the drawer was dismissed. Following a tree link passes false:
         a navigation is about to replace the page, and yanking focus back to the
         toggle would fight it. */
      var back = navReturnFocus || btn;
      if (back && back.focus) back.focus();
      navReturnFocus = null;
    }
  }

  document.addEventListener("click", function (e) {
    if (e.target.closest("[data-tx-nav-toggle]")) {
      setNavOpen(!document.body.classList.contains("tx-nav-open"));
      return;
    }
    if (!document.body.classList.contains("tx-nav-open")) return;
    // Close when a tree link is followed or the backdrop (outside the nav) is clicked.
    var nav = document.getElementById("tx_nav");
    if (e.target.closest(".tx-tree-link")) {
      setNavOpen(false, false);
    } else if (nav && !nav.contains(e.target)) {
      setNavOpen(false);
    }
  });
  document.addEventListener("keydown", function (e) {
    if (!document.body.classList.contains("tx-nav-open")) return;
    if (e.key === "Escape") {
      setNavOpen(false);
      return;
    }
    /* Keep Tab inside the open drawer. Without this, tabbing past the last tree
       link walks into the page behind the backdrop — content the user cannot see
       and cannot click. */
    if (e.key !== "Tab" || !navIsOverlay()) return;
    var nav = document.getElementById("tx_nav");
    if (!nav) return;
    var items = focusables(nav);
    if (!items.length) return;
    var first = items[0];
    var last = items[items.length - 1];
    if (!nav.contains(document.activeElement)) {
      e.preventDefault();
      (e.shiftKey ? last : first).focus();
    } else if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  });

  /* --- Resizable navigation panel (desktop only; persisted) --- */
  try {
    // Validate the stored width against the same 160–480px bound the drag and
    // the server-side inline style enforce, so a tampered/garbage localStorage
    // value can't apply an absurd or malformed --tx-nav-width.
    var savedW = localStorage.getItem("tx-nav-width");
    if (savedW && /^\d{2,3}px$/.test(savedW)) {
      var savedN = parseInt(savedW, 10);
      if (savedN >= 160 && savedN <= 480) {
        document.documentElement.style.setProperty("--tx-nav-width", savedW);
      }
    }
  } catch (_) {}
  (function () {
    function onMove(e) {
      var w = Math.min(480, Math.max(160, e.clientX));
      document.documentElement.style.setProperty("--tx-nav-width", w + "px");
    }
    function onUp() {
      document.body.style.userSelect = "";
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      var w = getComputedStyle(document.documentElement)
        .getPropertyValue("--tx-nav-width")
        .trim();
      try {
        localStorage.setItem("tx-nav-width", w);
      } catch (_) {}
      // Mirror to a cookie so the server can render the width inline on the next
      // first paint (no flash of the default-width sidebar before JS restores it).
      if (/^\d{2,3}px$/.test(w)) {
        document.cookie =
          "tx-nav-width=" + w + ";path=/;max-age=31536000;SameSite=Lax" +
          secureFlag();
      }
    }
    document.addEventListener("mousedown", function (e) {
      if (!e.target.closest("#tx_nav_resizer") || window.innerWidth < 768) return;
      e.preventDefault();
      document.body.style.userSelect = "none";
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  })();

  /* --- CodeMirror SQL editor enhancement (SQL mode only) ---
   * CodeMirror is 242 KB, over a third of the whole asset payload, and only
   * three pages carry a textarea.tx-sql-editor (the SQL console, the import form
   * and the stored-program editor).
   * base.html loads it up front only for those (Page.NeedsEditor); an htmx
   * navigation ONTO one of them swaps #page_content without re-running <head>,
   * so the same three files are injected on demand here. Injected <script
   * src>/<link href> point at our own origin, so the strict CSP (script-src
   * 'self', no unsafe-inline) is satisfied without an inline script. */
  /* Stamped with the build's asset fingerprint, exactly as the <head> stamps the
     rest: without it these three lazily-loaded files would be the only assets
     still revalidating every hour. base.html publishes the value in a meta tag. */
  function assetURL(path) {
    var m = document.querySelector('meta[name="asset-version"]');
    return m && m.content ? path + "?v=" + m.content : path;
  }
  var CM_CSS = assetURL("/static/vendor/codemirror/codemirror.min.css");
  var CM_CORE = assetURL("/static/vendor/codemirror/codemirror.min.js");
  var CM_SQL = assetURL("/static/vendor/codemirror/sql.min.js");

  /* Inserted BEFORE tablex.css, not appended, so the cascade matches a hard
     load: base.html puts the editor's stylesheet ahead of ours (line order
     there is the contract), and ours deliberately overrides some of it — the
     editor's own `.CodeMirror { height: 300px }` and font stack among them.
     Appending would have let the vendor rules win, so the console rendered
     one way on a fresh load and another after an htmx navigation.
     Matched on the href PREFIX because every asset URL carries a ?v=
     fingerprint; if tablex.css is somehow absent, appending is still better
     than not loading the editor's styles at all. */
  function loadStylesheetOnce(href) {
    if (document.querySelector('link[rel="stylesheet"][href="' + href + '"]')) return;
    var link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = href;
    var ours = document.querySelector('link[rel="stylesheet"][href^="/static/css/tablex.css"]');
    if (ours && ours.parentNode) {
      ours.parentNode.insertBefore(link, ours);
      return;
    }
    document.head.appendChild(link);
  }

  // loadScriptOnce fetches src at most once, no matter how many swaps race to
  // ask for it: a second caller arriving mid-flight attaches to the pending
  // element instead of adding another. done is always called (failures resolve
  // too — a missing editor degrades to a plain textarea, never a stuck page).
  function loadScriptOnce(src, done) {
    var existing = document.querySelector('script[src="' + src + '"]');
    if (existing) {
      if (existing.getAttribute("data-tx-loaded") === "1") {
        done();
      } else {
        existing.addEventListener("load", done);
        existing.addEventListener("error", done);
      }
      return;
    }
    var s = document.createElement("script");
    s.src = src;
    var finish = function () {
      s.setAttribute("data-tx-loaded", "1");
      done();
    };
    s.addEventListener("load", finish);
    s.addEventListener("error", finish);
    document.head.appendChild(s);
  }

  // ensureCodeMirror resolves once the library and its SQL mode are usable.
  function ensureCodeMirror(done) {
    if (typeof CodeMirror !== "undefined") {
      done(); // base.html already loaded it for this page
      return;
    }
    loadStylesheetOnce(CM_CSS);
    loadScriptOnce(CM_CORE, function () {
      // The SQL mode registers itself on the core, so it must load after it.
      loadScriptOnce(CM_SQL, done);
    });
  }

  /* Submit the form a SQL editor belongs to. requestSubmit rather than submit so
     validation and the submit event still run — htmx listens for that event, so
     calling form.submit() would bypass the swap and do a full page load. */
  function submitEditorForm(cm) {
    var ta = cm && cm.getTextArea ? cm.getTextArea() : null;
    if (ta) cm.save(); // flush the widget into the textarea first
    var form = ta && ta.closest ? ta.closest("form") : null;
    if (!form) return;
    if (form.requestSubmit) {
      form.requestSubmit();
    } else {
      form.submit();
    }
  }

  /* The same shortcut for the plain textarea: before CodeMirror has loaded, and
     for anyone running without it. */
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Enter" || !(e.ctrlKey || e.metaKey)) return;
    var ta = e.target;
    if (!ta || !ta.classList || !ta.classList.contains("tx-sql-editor")) return;
    var form = ta.closest ? ta.closest("form") : null;
    if (!form) return;
    e.preventDefault();
    if (form.requestSubmit) {
      form.requestSubmit();
    } else {
      form.submit();
    }
  });

  function upgradeEditors(scope) {
    if (typeof CodeMirror === "undefined") return;
    scope
      .querySelectorAll("textarea.tx-sql-editor:not(.cm-ready)")
      .forEach(function (ta) {
        ta.classList.add("cm-ready");
        var cm = CodeMirror.fromTextArea(ta, {
          mode: "text/x-sql",
          lineNumbers: true,
          lineWrapping: true,
          indentUnit: 2,
          viewportMargin: Infinity,
          /* Run without reaching for the mouse — the shortcut every SQL client
             has. Both spellings, because CodeMirror maps Cmd to "Cmd" on macOS
             and Ctrl elsewhere, and it maps Enter itself so the newline is not
             inserted first. */
          extraKeys: {
            "Ctrl-Enter": submitEditorForm,
            "Cmd-Enter": submitEditorForm,
          },
        });
        ta.cmInstance = cm;
        cm.on("change", function (_cm, chg) {
          cm.save();
          /* CodeMirror replaces the textarea with its own widget, so typing in
             the console fires no input event on the form and cm.save() does not
             synthesize one. Without this the SQL console — the form most worth
             guarding — would never be marked dirty. "setValue" is how the editor
             gets (re)populated from the textarea, which is not a user edit. */
          if (!chg || chg.origin !== "setValue") markDirty(ta);
        });
      });
  }

  function initCodeMirror(root) {
    var scope = root && root.querySelectorAll ? root : document;
    // Nothing to upgrade: return before touching the network, so a page without
    // an editor never pays for the library.
    if (!scope.querySelector("textarea.tx-sql-editor:not(.cm-ready)")) return;
    ensureCodeMirror(function () {
      upgradeEditors(scope);
    });
  }

  // Read-only highlighting for the definition panels on the routines, triggers
  // and events pages. Those pages do NOT set Page.NeedsEditor, so the 242 KB
  // library is fetched only if someone actually expands a panel — a listing
  // nobody opens costs nothing.
  //
  // The server-rendered <pre> is never replaced, only hidden: it stays the
  // source of truth so that htmx's history cache (which snapshots the rendered
  // DOM, CodeMirror widget and all) can be recovered from below, and so a failed
  // library load leaves a perfectly readable definition on screen.
  function upgradeDefinitions(scope) {
    if (typeof CodeMirror === "undefined") return;
    scope
      .querySelectorAll("pre.tx-defn-body:not(.cm-ready)")
      .forEach(function (pre) {
        pre.classList.add("cm-ready");
        var host = document.createElement("div");
        host.className = "tx-defn-cm";
        pre.parentNode.insertBefore(host, pre.nextSibling);
        CodeMirror(host, {
          value: pre.textContent,
          mode: "text/x-sql",
          lineNumbers: true,
          lineWrapping: true,
          readOnly: true,
          viewportMargin: Infinity,
        });
        pre.classList.add("tx-defn-hidden");
      });
  }

  function initDefinitions(root) {
    var scope = root && root.querySelectorAll ? root : document;
    if (!scope.querySelector("pre.tx-defn-body:not(.cm-ready)")) return;
    ensureCodeMirror(function () {
      upgradeDefinitions(scope);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    initCodeMirror(document);
    initDefinitions(document);
  });
  document.addEventListener("htmx:afterSettle", function (e) {
    initCodeMirror(e.target || document);
    initDefinitions(e.target || document);
    markActiveNavNode();
    /* A tree refresh replaces the nodes the filter had hidden, so re-apply it —
       otherwise the box still holds the query while the full tree is back. */
    applyNavFilter();
    // Move focus to the freshly-swapped main region so keyboard/SR users land on
    // the new page (only when the swap actually targeted #page_content).
    var pc = document.getElementById("page_content");
    var landed = pc && e.target && (e.target === pc || e.target.id === "page_content");
    if (landed) {
      pc.focus();
    } else {
      /* The swap went somewhere else — the nav tree, an out-of-band region — so
         nothing moved focus and a flash it brought with it would go unheard.
         Announce it. When focus DID land in #page_content the reader already
         reads the region from the top, flash included, so announcing there too
         would just say it twice. */
      var flash = (e.target || document).querySelector(".tx-alert .tx-alert-msg");
      if (flash) announce(flash.textContent.trim());
    }
  });
  // Back/forward restores the DOM from htmx's history cache: the snapshot
  // contains CodeMirror's rendered widget as dead markup and the textarea still
  // carries cm-ready, so without this the editor comes back inert. Drop the
  // stale widgets and re-initialize from the textareas.
  document.addEventListener("htmx:historyRestore", function () {
    // Drop each definition panel's whole CodeMirror host and reveal the <pre>
    // it was hiding. This runs before the blanket .CodeMirror sweep so the
    // widget goes with its host rather than leaving an empty container behind.
    document.querySelectorAll(".tx-defn-cm").forEach(function (el) {
      el.remove();
    });
    document.querySelectorAll("pre.tx-defn-body").forEach(function (pre) {
      pre.classList.remove("cm-ready", "tx-defn-hidden");
    });
    document.querySelectorAll(".CodeMirror").forEach(function (el) {
      el.remove();
    });
    document
      .querySelectorAll("textarea.tx-sql-editor.cm-ready")
      .forEach(function (ta) {
        ta.classList.remove("cm-ready");
      });
    initCodeMirror(document);
    initDefinitions(document);
    markActiveNavNode();
  });

  /* --- Alpine components ---
   * Built against @alpinejs/csp, which avoids new Function/eval so the strict
   * CSP (no unsafe-eval) holds. That build still parses a useful expression
   * subset (incl. simple comparisons), but TableX standardizes on Alpine.data()
   * property/getter references by convention for consistency. */
  document.addEventListener("alpine:init", function () {
    var Alpine = window.Alpine;

    // Export form: the Structure/Data/DROP options apply only to SQL, so hide
    // them for every data format (CSV/JSON/XML). The test is "is it SQL", not a
    // list of the others, so a new format needs no change here. format follows
    // the radios; isSQL is a getter so the CSP build never needs to evaluate an
    // inline expression.
    Alpine.data("exportForm", function () {
      return {
        format: "sql",
        get isSQL() {
          return this.format === "sql";
        },
      };
    });

    Alpine.data("loginForm", function () {
      return {
        // Set from the form's data-engine in init() — the server picks the
        // pre-selected engine (the first one the registry offers), so no engine
        // name appears in this file.
        engine: "",
        server: "",
        // Populated from each engine <option>'s data-port in init(), so the
        // default ports come from the dialect's DefaultPort() (single source of
        // truth) rather than being hardcoded here and drifting.
        ports: {},
        // Per-engine presentation metadata, read from each engine <option>'s
        // data attributes (server-rendered from the dialect's capabilities and
        // login hints) — this script never names an engine.
        meta: {},
        // The auto-default this form itself applied to the database field
        // (never a user-typed value), so switching engines clears only it.
        dbAuto: "",
        init: function () {
          if (this.$root && this.$root.dataset.engine) {
            this.engine = this.$root.dataset.engine;
          }
          var engSel = this.$root.querySelector('select[name="engine"]');
          if (engSel) {
            for (var i = 0; i < engSel.options.length; i++) {
              var opt = engSel.options[i];
              var port = parseInt(opt.dataset.port, 10);
              if (port > 0) this.ports[opt.value] = port;
              this.meta[opt.value] = {
                ssl: opt.dataset.showSslmode === "1",
                sslNote: opt.dataset.sslNote || "",
                dbLabel: opt.dataset.dbLabel || "Database",
                dbPlaceholder: opt.dataset.dbPlaceholder || "optional",
                dbDefault: opt.dataset.dbDefault || "",
                dbNote: opt.dataset.dbNote || "",
              };
            }
          }
          // Bind to the select's real value: when ad-hoc login is disabled there
          // is no "" option, so the model must follow the first predefined server.
          var sel = this.$root.querySelector('select[name="server"]');
          if (sel) this.server = sel.value;
          this.syncDatabaseDefault();
        },
        engineMeta: function () {
          return this.meta[this.engine] || {};
        },
        get adhoc() {
          return this.server === "";
        },
        // Ad-hoc connections are always network engines: SQLite is reachable
        // only through an operator-configured predefined server.
        get showNetwork() {
          return this.server === "";
        },
        // The <option> for the selected predefined server, or null for ad-hoc.
        selectedServer: function () {
          var sel = this.$root.querySelector('select[name="server"]');
          if (!sel) return null;
          for (var i = 0; i < sel.options.length; i++) {
            if (sel.options[i].value === this.server) return sel.options[i];
          }
          return null;
        },
        // Credentials: ad-hoc is always a network engine (username + password);
        // a predefined server only shows the fields its config leaves empty.
        get showUser() {
          if (this.adhoc) return true;
          var o = this.selectedServer();
          return !!(o && o.dataset.needsUser === "1");
        },
        get showPassword() {
          if (this.adhoc) return true;
          var o = this.selectedServer();
          return !!(o && o.dataset.needsPassword === "1");
        },
        get showCredentials() {
          return this.showUser || this.showPassword;
        },
        // Some engines' ad-hoc forms expose an extra SSL-mode selector
        // (data-show-sslmode on the engine option).
        get showSSL() {
          return !!this.engineMeta().ssl;
        },
        // Database-field presentation comes from the engine option's dataset
        // (e.g. PostgreSQL labels it as the maintenance DB; the server-side
        // NormalizeParams applies the same default).
        get dbLabel() {
          return this.engineMeta().dbLabel || "Database";
        },
        get dbPlaceholder() {
          return this.engineMeta().dbPlaceholder || "optional";
        },
        get sslNote() {
          return this.engineMeta().sslNote || "";
        },
        get dbNote() {
          return this.engineMeta().dbNote || "";
        },
        onEngine: function () {
          var p = this.$refs.port;
          var def = this.ports[this.engine];
          if (p && typeof def === "number" && def > 0) p.value = def;
          this.syncDatabaseDefault();
        },
        // Pre-fill the engine's database default (only into an empty field) and
        // clear it again when switching away — tracked via dbAuto, so ONLY the
        // value this form applied is ever cleared, never one the user typed
        // (e.g. their own DB on a managed host).
        syncDatabaseDefault: function () {
          var db = this.$root.querySelector('input[name="database"]');
          if (!db) return;
          var def = this.engineMeta().dbDefault || "";
          if (def) {
            if (db.value.trim() === "") {
              db.value = def;
              this.dbAuto = def;
            }
          } else if (this.dbAuto && db.value.trim() === this.dbAuto) {
            db.value = "";
            this.dbAuto = "";
          }
        },
      };
    });

    // navSelect turns a <select> whose option values are URLs into a
    // navigation control. The server builds every destination, so nothing here
    // assembles a query string — the bug that pattern caused (a client-side
    // rebuild that could only carry one sort key) is why it is gone.
    Alpine.data("navSelect", function () {
      return {
        go: function (e) {
          var url = (e && e.target ? e.target : this.$el).value;
          if (!url) {
            return;
          }
          window.htmx.ajax("GET", url, { target: "#page_content", push: url });
        },
      };
    });

    // rowFilter narrows the rows ALREADY rendered on this page. It is not a
    // WHERE clause and never re-queries — the classic "Filter rows" control,
    // which is purely presentational. Matching is case-insensitive
    // over each row's text, and the count is announced through an aria-live
    // region so the result is not a silent visual change.
    Alpine.data("rowFilter", function () {
      return {
        apply: function () {
          var needle = (this.$refs.q.value || "").toLowerCase();
          var rows = this.$root
            .closest(".tx-browse")
            .querySelectorAll("tr.tx-row");
          var shown = 0;
          rows.forEach(function (tr) {
            var hit = !needle || tr.textContent.toLowerCase().indexOf(needle) !== -1;
            tr.hidden = !hit;
            if (hit) {
              shown++;
            }
          });
          this.$refs.count.textContent = needle
            ? shown + " of " + rows.length + " rows shown"
            : "";
        },
      };
    });

    Alpine.data("bulkRows", function () {
      return {
        toggleAll: function (e) {
          var src =
            e && e.target
              ? e.target
              : this.$root.querySelector(".tx-check-all");
          var checked = src.checked;
          this.$root.querySelectorAll(".tx-check").forEach(function (c) {
            c.checked = checked;
          });
          this.$root.querySelectorAll(".tx-check-all").forEach(function (c) {
            c.checked = checked;
          });
        },
      };
    });

    // Export form's per-table picker. Progressive enhancement only: the boxes
    // render checked and work without this — these two buttons just save the
    // clicking on a database with many tables.
    Alpine.data("objectPicker", function () {
      return {
        setAll: function (checked) {
          this.$root
            .querySelectorAll('input[type="checkbox"]')
            .forEach(function (c) {
              c.checked = checked;
            });
        },
        selectAll: function () {
          this.setAll(true);
        },
        selectNone: function () {
          this.setAll(false);
        },
      };
    });

    Alpine.data("sqlConsole", function () {
      return {
        run: function () {
          var ta = this.$root.querySelector("textarea.tx-sql-editor");
          if (ta && ta.cmInstance) ta.cmInstance.save();
        },
        useHistory: function (e) {
          var el = e && e.target ? e.target.closest("[data-sql]") : null;
          if (!el) return;
          var sql = el.getAttribute("data-sql");
          var ta = this.$root.querySelector("textarea.tx-sql-editor");
          if (!ta) return;
          ta.value = sql;
          if (ta.cmInstance) ta.cmInstance.setValue(sql);
        },
      };
    });

    /* Create-table form: add/remove column rows. The server renders a fixed
     * batch of indexed rows (the no-JS fallback); this enhancement clones the
     * last row's DOM node and renumbers the clone's input names in plain JS —
     * the CSP Alpine build cannot evaluate ':name' expression bindings, so
     * reactive name computation is off the table by design. The server-side
     * parser scans up to 50 indexed rows; addRow stops there. */
    Alpine.data("createTableRows", function () {
      return {
        addRow: function () {
          var body = this.$root.querySelector("tbody");
          var rows = body.querySelectorAll("tr.ct-row");
          if (!rows.length || rows.length >= 50) return;
          var clone = rows[rows.length - 1].cloneNode(true);
          var next = rows.length;
          /* textarea included: the ENUM/SET values box (col_values_N) must be
           * renumbered too, or every added row posts its values under the
           * PREVIOUS row's index and the server rejects the whole form with
           * "needs at least one value". */
          clone.querySelectorAll("input, select, textarea").forEach(function (el) {
            el.name = el.name.replace(/_\d+$/, "_" + next);
            if (el.type === "checkbox") {
              // Fresh rows start like the server-rendered ones: nullable
              // checked, PK unchecked.
              el.checked = el.name.indexOf("col_nullable") === 0;
            } else if (el.tagName === "SELECT") {
              el.selectedIndex = 0;
            } else {
              el.value = "";
            }
          });
          body.appendChild(clone);
        },
        removeRow: function () {
          var rows = this.$root.querySelectorAll("tbody tr.ct-row");
          if (rows.length > 1) rows[rows.length - 1].remove();
        },
      };
    });
  });
})();
