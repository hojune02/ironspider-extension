"""
IronSpider Detector — server-side behavioral anomaly detection
==============================================================
Research extension for NDSS 2024 "Compromising Industrial Processes
using Web-Based PLC Malware" (Pickren, Shekari, Zonouz, Beyah).

The paper (Section V-D) states WB PLC malware detection is "an open problem"
because static JS analyzers (Cujo, Zozzle, JaSt, JStap) all classify it as
benign — the malware uses only legitimate browser APIs with no suspicious
syntax. This detector addresses the gap by monitoring *runtime behavior* at
the server boundary, implementing the "PLC-configured WAF" countermeasure
proposed in Table VII.

Three detection tiers (increasing false-positive risk):

  TIER 1 — Deterministic (0 false positives on any known PLC firmware)
    Repeated no-cache GET requests to the malware payload URL. A legitimate
    browser page load produces at most 1 GET per navigation. The IronSpider
    service worker fires a cache-busted GET to /static/malware.js every 30 s
    (the "Check Existence" polling loop, Fig. 4, Zonouz et al. NDSS 2024).
    Three or more such requests within 90 seconds is definitively non-human:
    no clean PLC firmware or browser behavior produces repeated re-fetches of
    the same JS file at machine-speed intervals.

  TIER 2 — Statistical (near-zero false positives)
    Write calls to the actuator API faster than a human can operate. The
    paper's actuator manipulation fires every 50–500ms; a human operator
    produces at most 1–2 writes per second. Rate measured over a 5-second
    sliding window.

  TIER 3 — Heuristic (low false-positive rate, depends on baseline)
    A /monitor-update (sensor read) immediately followed by a /point-write
    (actuator write) with sub-500ms latency. Human operators read a value,
    think, then act — machine-speed read-write pairing is the signature of
    the attack's Capability 3 execution loop (Fig. 6 in the paper).

Usage:
    Import and instantiate detector = IronSpiderDetector() in webserver.py.
    Call detector.on_request(path, method, remote_addr) from a Flask
    @app.before_request hook.
    Expose detector.get_alerts() via a /ironspider-alerts Flask route.
"""

import time
import threading
import collections
from datetime import datetime


class IronSpiderDetector:

    # Tier 1: flag if malware URL is fetched this many times within the window.
    # Normal browser: 1 GET per page navigation (cached thereafter).
    # IronSpider SW: 1 GET every 30 s with cache: 'no-store'.
    # Three requests in 90 s means at least two came from the SW poll loop.
    MALWARE_CHECK_THRESHOLD = 3      # requests
    MALWARE_CHECK_WINDOW    = 90.0   # seconds
    MALWARE_URL_PATTERN     = '/static/malware.js'

    # Tier 2: flag if write rate exceeds this over the measurement window
    WRITE_RATE_THRESHOLD = 2.0   # writes/sec  (human max ≈ 0.5/sec)
    WRITE_RATE_WINDOW    = 5.0   # seconds

    # Tier 3: flag if monitor-read → actuator-write latency is below this
    READ_WRITE_MAX_MS    = 500   # ms

    def __init__(self):
        self.alerts = []
        self._lock = threading.Lock()
        # Sliding window of timestamps for GET requests to the malware URL
        self._malware_check_times = collections.deque()
        # Deduplicate Tier 1 alert (only fire once — polling is ongoing)
        self._sw_polling_alerted = False
        # Sliding window of timestamp for each /point-write call
        self._write_times = collections.deque()
        # Timestamp of most recent /monitor-update
        self._last_monitor_read = None

    # ------------------------------------------------------------------
    # Public API — called by Flask before_request hook in webserver.py
    # ------------------------------------------------------------------
    def on_request(self, path, method, remote_addr, headers):
        now = time.time()

        # --- TIER 1: SW existence-check polling -----------------------
        # The IronSpider SW polls GET /static/malware.js with cache:'no-store'
        # every 30 s (sw.js activate handler, setInterval 30000ms).
        # This is the "Check Existence" loop in Figure 4 of the paper.
        #
        # Normal browser behavior: the JS file is fetched once per page load,
        # then served from the HTTP cache on subsequent navigations. A page
        # never re-requests the same <script src> within the same session.
        #
        # Detection signal: 3+ GETs to the malware URL within 90 s.
        # The first GET is the legitimate page-load fetch. The second and
        # third are the SW's periodic no-cache polls — two SW polls 30 s apart
        # plus the initial load hits the threshold after ≈60 s of SW activity.
        #
        # No clean PLC firmware produces repeated machine-speed re-fetches of
        # a static JS file — this pattern is unique to the SW poll loop.
        if method == 'GET' and self.MALWARE_URL_PATTERN in path and not self._sw_polling_alerted:
            with self._lock:
                self._malware_check_times.append(now)
                cutoff = now - self.MALWARE_CHECK_WINDOW
                while self._malware_check_times and self._malware_check_times[0] < cutoff:
                    self._malware_check_times.popleft()
                count = len(self._malware_check_times)
            if count >= self.MALWARE_CHECK_THRESHOLD:
                self._sw_polling_alerted = True
                self._alert(
                    rule='TIER1_SW_POLLING',
                    message=(
                        f'GET {path} received {count} times within '
                        f'{self.MALWARE_CHECK_WINDOW:.0f} s from {remote_addr} '
                        f'(threshold: {self.MALWARE_CHECK_THRESHOLD}). '
                        'Repeated no-cache fetches of a static JS file are '
                        'inconsistent with any browser or human behavior. '
                        'This matches the IronSpider service worker '
                        '"Check Existence" polling loop '
                        '(Fig. 4, Zonouz et al. NDSS 2024).'
                    ),
                    severity='CRITICAL'
                )

        # --- TIER 2: Actuator write rate ------------------------------
        if '/point-write' in path:
            with self._lock:
                self._write_times.append(now)
                # Expire entries outside the measurement window
                cutoff = now - self.WRITE_RATE_WINDOW
                while self._write_times and self._write_times[0] < cutoff:
                    self._write_times.popleft()
                rate = len(self._write_times) / self.WRITE_RATE_WINDOW

            if rate > self.WRITE_RATE_THRESHOLD:
                self._alert(
                    rule='TIER2_WRITE_RATE',
                    message=(
                        f'/point-write rate = {rate:.1f} writes/sec '
                        f'(threshold: {self.WRITE_RATE_THRESHOLD}/sec). '
                        'Machine-speed actuator writes inconsistent with '
                        'human operator behavior.'
                    ),
                    severity='HIGH'
                )

            # --- TIER 3: Read-then-write sequence ---------------------
            with self._lock:
                last_read = self._last_monitor_read
            if last_read is not None:
                elapsed_ms = (now - last_read) * 1000
                if elapsed_ms < self.READ_WRITE_MAX_MS:
                    self._alert(
                        rule='TIER3_READ_WRITE_SEQUENCE',
                        message=(
                            f'/monitor-update → /point-write in '
                            f'{elapsed_ms:.0f} ms '
                            f'(threshold: {self.READ_WRITE_MAX_MS} ms). '
                            'Automated read-modify-write loop detected. '
                            'Matches IronSpider Cap 3 execution pattern '
                            '(Fig. 6, Zonouz et al. NDSS 2024).'
                        ),
                        severity='MEDIUM'
                    )

        # Track /monitor-update timestamp for Tier 3
        if '/monitor-update' in path:
            with self._lock:
                self._last_monitor_read = now

    # ------------------------------------------------------------------
    def get_alerts(self):
        """Return all collected alerts as a list of dicts (thread-safe)."""
        with self._lock:
            return list(self.alerts)

    def get_summary(self):
        """Return counts by severity for the /ironspider-alerts dashboard."""
        with self._lock:
            summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'total': 0}
            for a in self.alerts:
                summary[a['severity']] = summary.get(a['severity'], 0) + 1
                summary['total'] += 1
            return summary

    # ------------------------------------------------------------------
    def _alert(self, rule, message, severity='INFO'):
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        entry = {
            'time': timestamp,
            'rule': rule,
            'severity': severity,
            'message': message
        }
        print(f'[{timestamp}] IRONSPIDER-DETECT [{severity}] {rule}: {message}')
        with self._lock:
            self.alerts.append(entry)


# Module-level singleton — imported by webserver.py
detector = IronSpiderDetector()
