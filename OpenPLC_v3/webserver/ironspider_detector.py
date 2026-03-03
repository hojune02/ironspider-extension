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
    Two signals must both be present on a GET request:
      Sec-Fetch-Dest: empty  — the browser sets this for all programmatic
        fetch() API calls. Page <script src> loads send Sec-Fetch-Dest: script.
        Note: Chrome/Brave do NOT add Cache-Control for fetch({cache:'no-store'})
        — the cache mode is handled internally without a request header.
      Referer ends with .js  — SW fetch() calls carry the SW script URL as
        Referer (e.g. /static/sw.js). Regular page fetch() carries the page
        URL (e.g. /monitoring), which does not end in .js.
    3+ requests matching both signals within 90 s confirms automated polling
    from a JS file context (Service Worker). Filename-agnostic: detects
    malware under any name, not just malware.js.

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

    # Tier 1: flag when Sec-Fetch-Dest: empty + Referer-ends-.js requests
    # accumulate past this threshold. Both signals together identify a SW fetch()
    # loop — page <script> loads and page-originated fetch() calls don't match.
    MALWARE_CHECK_THRESHOLD      = 3      # requests within window to trigger
    MALWARE_CHECK_WINDOW         = 90.0   # seconds
    MALWARE_CHECK_ALERT_INTERVAL = 90.0   # seconds between repeated alerts

    # Tier 2: flag if write rate exceeds this over the measurement window
    WRITE_RATE_THRESHOLD = 2.0   # writes/sec  (human max ≈ 0.5/sec)
    WRITE_RATE_WINDOW    = 5.0   # seconds

    # Tier 3: flag if monitor-read → actuator-write latency is below this
    READ_WRITE_MAX_MS    = 500   # ms

    def __init__(self):
        self.alerts = []
        self._lock = threading.Lock()
        # Sliding window of timestamps for Tier 1 matching requests
        self._malware_check_times = collections.deque()
        # Timestamp of last Tier 1 alert (None = never fired)
        self._last_sw_polling_alert = None
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
        # Two signals together identify a Service Worker fetch() polling loop:
        #   Sec-Fetch-Dest: empty  → request came from fetch() API, not a
        #                            <script src> tag (which sends 'script')
        #   Referer ends with .js  → fetch originated from a JS file (e.g. SW
        #                            at /static/sw.js), not from a page URL
        # Chrome/Brave do NOT add Cache-Control for fetch({cache:'no-store'}) —
        # Sec-Fetch-Dest is the correct discriminator instead.
        referer = headers.get('Referer', '')
        is_sw_fetch = (
            method == 'GET'
            and headers.get('Sec-Fetch-Dest') == 'empty'
            and referer.endswith('.js')
        )
        if is_sw_fetch:
            with self._lock:
                self._malware_check_times.append(now)
                cutoff = now - self.MALWARE_CHECK_WINDOW
                while self._malware_check_times and self._malware_check_times[0] < cutoff:
                    self._malware_check_times.popleft()
                count = len(self._malware_check_times)
                last_alert = self._last_sw_polling_alert
            cooldown_elapsed = (last_alert is None or
                                (now - last_alert) >= self.MALWARE_CHECK_ALERT_INTERVAL)
            if count >= self.MALWARE_CHECK_THRESHOLD and cooldown_elapsed:
                with self._lock:
                    self._last_sw_polling_alert = now
                self._alert(
                    rule='TIER1_SW_POLLING',
                    message=(
                        f'fetch() from JS context ({referer}) to {path} '
                        f'detected {count} times within {self.MALWARE_CHECK_WINDOW:.0f} s '
                        f'from {remote_addr} (threshold: {self.MALWARE_CHECK_THRESHOLD}). '
                        'Sec-Fetch-Dest: empty confirms fetch() API call (not <script> tag). '
                        'Referer ending in .js confirms origin from a JS file (Service Worker). '
                        'Matches the IronSpider SW existence-check polling loop '
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
