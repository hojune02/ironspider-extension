#!/usr/bin/env node
// server.js — IronSpider Resurrection Testbed HTTPS server
// Research/Educational: NDSS 2024 replication study
//
// Endpoints:
//   GET  /             → serves public/index.html
//   GET  /malware.js   → serves public/malware.js (returns 404 after factory reset)
//   GET  /sw.js        → serves public/sw.js
//   POST /upload       → simulates PLC file-write API (CVE-2022-45140 analogue)
//   POST /reset        → simulates factory reset (deletes public/malware.js)
//   GET  /*            → static file server from public/

'use strict';

const https = require('https');
const fs    = require('fs');
const path  = require('path');

const PORT       = 8443;
const PUBLIC_DIR = path.join(__dirname, 'public');
const CERT_KEY   = path.join(__dirname, 'certs', 'localhost-key.pem');
const CERT_CRT   = path.join(__dirname, 'certs', 'localhost.pem');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'text/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json',
  '.ico':  'image/x-icon',
  '.png':  'image/png',
};

// ── Load TLS certificates ──────────────────────────────────────────────────
let key, cert;
try {
  key  = fs.readFileSync(CERT_KEY);
  cert = fs.readFileSync(CERT_CRT);
} catch (_) {
  console.error('[ERROR] TLS certificates not found in ./certs/');
  console.error('        Run:  bash setup.sh');
  process.exit(1);
}

// ── Logging ───────────────────────────────────────────────────────────────
function log(method, url, note) {
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 23);
  console.log(`[${ts}]  ${method.padEnd(6)} ${url.padEnd(30)} ${note || ''}`);
}

// ── Request handler ───────────────────────────────────────────────────────
function handleRequest(req, res) {
  // Allow SW to control the entire origin
  res.setHeader('Service-Worker-Allowed', '/');

  // ── POST /upload — simulated PLC file-write API ──────────────────────────
  // Real IronSpider uses CVE-2022-45140: arbitrary write via network_config API.
  // Here we expose a simple JSON endpoint that the SW calls same-origin.
  if (req.method === 'POST' && req.url === '/upload') {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 2e6) { req.destroy(); return; } // 2 MB limit
    });
    req.on('end', () => {
      try {
        const { filename, content } = JSON.parse(body);
        // Accept only simple *.js filenames; no path traversal
        if (!/^[\w-]+\.js$/.test(filename)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Invalid filename' }));
          return;
        }
        const dest = path.join(PUBLIC_DIR, filename);
        fs.writeFileSync(dest, content, 'utf8');
        log(req.method, req.url, `*** RESURRECTION: wrote ${filename} (${content.length} bytes)`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, message: `${filename} uploaded (${content.length} bytes)` }));
      } catch (err) {
        log(req.method, req.url, `ERROR: ${err.message}`);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: err.message }));
      }
    });
    return;
  }

  // ── POST /reset — simulate factory reset ─────────────────────────────────
  if (req.method === 'POST' && req.url === '/reset') {
    const malwarePath = path.join(PUBLIC_DIR, 'malware.js');
    if (fs.existsSync(malwarePath)) {
      fs.unlinkSync(malwarePath);
      log(req.method, req.url, '*** FACTORY RESET: malware.js deleted from disk');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, message: 'Factory reset complete — malware.js deleted' }));
    } else {
      log(req.method, req.url, 'malware.js already absent');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, message: 'malware.js was already absent' }));
    }
    return;
  }

  // ── Static file server ───────────────────────────────────────────────────
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405); res.end('Method Not Allowed'); return;
  }

  // Strip query string, resolve to public/ directory
  let urlPath = req.url.split('?')[0].split('#')[0];
  if (urlPath === '/') urlPath = '/index.html';

  // Prevent path traversal
  const resolved = path.normalize(urlPath).replace(/^(\.\.[/\\])+/, '');
  const filePath = path.join(PUBLIC_DIR, resolved);
  if (!filePath.startsWith(PUBLIC_DIR + path.sep) && filePath !== PUBLIC_DIR) {
    res.writeHead(403); res.end('Forbidden'); return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      log(req.method, req.url, '404');
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    const ct  = MIME[ext] || 'application/octet-stream';
    log(req.method, req.url, `200 (${data.length}b)`);
    res.writeHead(200, {
      'Content-Type':   ct,
      'Content-Length': data.length,
      // Disable browser HTTP cache so factory reset / resurrection are visible immediately
      'Cache-Control':  'no-store',
    });
    res.end(data);
  });
}

// ── Start ─────────────────────────────────────────────────────────────────
const server = https.createServer({ key, cert }, handleRequest);
server.listen(PORT, '127.0.0.1', () => {
  const bar = '─'.repeat(58);
  console.log(bar);
  console.log('  IronSpider Resurrection Testbed');
  console.log('  NDSS 2024 — Educational Replication (Pickren et al.)');
  console.log(bar);
  console.log(`  URL        https://localhost:${PORT}/`);
  console.log(`  Public     ${PUBLIC_DIR}`);
  console.log(`  TLS cert   ./certs/localhost.pem`);
  console.log(bar);
  console.log('  Endpoints:');
  console.log('    GET  /* (static)      Serve files from public/');
  console.log('    POST /reset           Simulate factory reset (delete malware.js)');
  console.log('    POST /upload          Simulate PLC file-write API (resurrection target)');
  console.log(bar);
});
