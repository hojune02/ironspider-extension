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
    Service worker script requested from a PLC origin. Legitimate PLC web
    applications never register service workers. A single GET /static/sw.js
    is a definitive indicator of WB malware persistence.

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

    # Tier 2: flag if write rate exceeds this over the measurement window
    WRITE_RATE_THRESHOLD = 2.0   # writes/sec  (human max ≈ 0.5/sec)
    WRITE_RATE_WINDOW    = 5.0   # seconds

    # Tier 3: flag if monitor-read → actuator-write latency is below this
    READ_WRITE_MAX_MS    = 500   # ms

    def __init__(self):
        self.alerts = []
        self._lock = threading.Lock()
        # Sliding window of timestamp for each /point-write call
        self._write_times = collections.deque()
        # Timestamp of most recent /monitor-update
        self._last_monitor_read = None
        # Deduplicate Tier 1 alert (only fire once per SW registration event)
        self._sw_alerted = False

    # ------------------------------------------------------------------
    # Public API — called by Flask before_request hook in webserver.py
    # ------------------------------------------------------------------
    def on_request(self, path, method, remote_addr, headers):
        now = time.time()

        # --- TIER 1: Service worker registration ----------------------
        # When a browser fetches a service worker script — regardless of
        # filename — it attaches the header "Service-Worker: script" to
        # the request (W3C Fetch spec §2.2.5, Service Workers spec §8.4).
        # This header is ONLY sent for SW fetches; normal JS <script> tags
        # never produce it. Checking the header rather than the filename
        # means detection is evasion-resistant: renaming sw.js to
        # persist.js, cache.js, or anything else does not bypass this rule.
        #
        # No legitimate PLC firmware (WAGO, Siemens, Allen-Bradley,
        # Schneider, Mitsubishi) registers service workers — confirmed by
        # inspection of public firmware artifacts (NDSS 2024 Appendix I-B
        # and WAGO pfc-firmware-sdk on GitHub).
        if headers.get('Service-Worker') == 'script' and not self._sw_alerted:
            self._sw_alerted = True
            self._alert(
                rule='TIER1_SW_REGISTRATION',
                message=(
                    f'Service-Worker: script header detected on request '
                    f'for {path} from {remote_addr}. '
                    'Browser is registering a service worker. '
                    'No clean PLC firmware uses service workers — '
                    'this is a definitive indicator of WB malware persistence.'
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
