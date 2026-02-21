# Qualitative Analysis of JavaScript Functionality Added in WAGO v4.02.13

**Method**: JS file diff between v3.0.39 (65 files) and v4.02.13 (98 files), with snippet
inspection of each new plugin's main entry point.

---

## 1. Architectural Shift: Monolith → Plugin System

The most structurally significant change is the replacement of a flat directory of 64
loosely-coupled files (`/wbm/js/*.js`) with a modular plugin system. Each feature is now
a self-contained webpack bundle (`wbm-<name>/<name>.js`) that registers itself via
`base.plugin.register()`. Plugins load platform-specific data transformations from a
`platform/pfcXXX/parameter/transforms/` subdirectory, separating UI logic from
device-specific parameter mapping. Only 7 filenames carried over (all relocated to their
respective plugin directories); 58 old files were replaced and 89 net-new files added.

Security consequence: modularity means new capability can be silently added as an
additional plugin file—a smaller footprint change than rewriting a monolithic script. The
plugin loader (`pfc.js`) is the new single point of trust; compromising it (as IronSpider
does at the WBM layer) gives control over all plugins simultaneously.

---

## 2. Security and Authentication Modules (12 new files)

**AIDE (Advanced Intrusion Detection Environment)** — `wbm-aide` v1.1.1 (2022): A web
UI wrapping the AIDE filesystem integrity checker. Operators can trigger `init`,
`check`, `update`, or `readlog` from the browser and configure automatic polling. The
plugin itself notes: *"Remember to write down the hash of the database and compare it
with the log to ensure it has not been tampered with."* Critically, this defense is
managed through the exact same web interface that IronSpider can compromise. A
web-based attacker with WBM access can read AIDE logs (to understand what is monitored)
or trigger an `init` to reset the baseline—neutralizing integrity checks from within
the browser.

**Firewall** — `wbm-firewall`: Four transform files cover iptables rules, ebtables (layer-2
MAC filtering), per-service toggles, and connection limits. The old firmware had separate
flat files (`firewall_general_configuration.js`, `firewall_service_configuration.js`,
etc.); the new version unifies these under one plugin with finer-grained control,
including per-interface rule ordering.

**wbm-certificate-uploads, wbm-security, wbm-user**: Certificate management,
general security settings, and user accounts are now first-class plugins. The
certificate upload surface is new (v3.0.39 had `tls.js` only); it now enables
uploading arbitrary CA/device certificates through the browser.

---

## 3. Industrial Protocol Expansion (12 new files)

**OPC UA** — `wbm-opcua` grew from one flat file (`opcua.js`) to 10 files, adding 8
certificate transforms: client-keys-certs, client-own-certs, client-rejected-certs,
client-trusted-certs, server-keys-certs, server-own-certs, server-rejected-certs,
server-trusted-certs. OPC UA is the primary IT/OT protocol bridge; this full PKI
management surface means the WBM now configures trust anchors for industrial
communication. An IronSpider-style attacker with WBM access could inject a malicious
trusted certificate, enabling man-in-the-middle on OPC UA sessions.

**WAGO Device Access (WDA)** — `wbm-wda` v1.0.2 (2022): Controls a single critical
parameter: `wda.allowunauth.scandevices`—a checkbox for allowing unauthenticated device
scanning. This is a discovery/reconnaissance-facilitation control exposed in the browser.

**BACnet** — Consolidated from three flat files into `wbm-bacnet` (one plugin, but with
more comprehensive configuration scope per the JS structure).

---

## 4. Remote Access and Cloud Connectivity (7 new files)

**Cloud Connectivity** — `wbm-cloud-connectivity` v1.14.11 (2023) is the single largest
new module. It supports six cloud platforms (WAGO Cloud, Azure, AWS, IBM, SAP IoT,
generic MQTT) with two simultaneous persistent connections. Configuration parameters
include MQTT hostname, port, client ID, TLS, WebSocket toggle, HTTP proxy, data
protocol (including Sparkplug B), caching to SD card, and MQTT Last Will. Cloud
credentials (username, password, CA/cert/key files) are stored and managed through the
web interface. This creates a persistent outbound MQTT channel—exactly the kind of
covert egress that IronSpider-style malware could abuse to tunnel commands or exfiltrate
sensor data while appearing to be legitimate telemetry traffic.

**OpenVPN/IPsec** — `wbm-openvpn-ipsec`: VPN tunnel configuration from the web UI.
Persistent encrypted tunnels from a PLC to attacker-controlled infrastructure, if
credentials are modified.

**Modem NG** — `wbm-modem-ng` + modem provider transforms: Cellular (LTE/4G) connectivity
management. Adds an alternative outbound path independent of the plant network.

---

## 5. Container and Software Infrastructure (4 new files)

**Docker** — `wbm-docker` v1.1.0 (2023): The most unexpected addition. A Docker
activation/deactivation UI on a PLC. The "Activating Docker" dialog notes it may take
up to a minute. Running containers on safety-critical ICS hardware introduces a container
escape attack path: a container breakout or malicious image gives direct access to the
host Linux kernel that drives the PLC runtime.

**IPK Uploads & Package Server** — `wbm-ipk-uploads` and `wbm-package-server` (with
`/wbm/firmware_backup_status` API endpoint): Browser-based software package upload and
a local package repository. This is a direct software supply chain injection vector if
authentication is bypassed (as with the CVEs exploited by IronSpider).

---

## 6. On-Device API Documentation

`openapi/redoc.standalone.js` ships the full Redoc API documentation renderer on the
device itself. This means the machine-readable API surface is self-describing—an
attacker who reaches the device can enumerate all supported REST endpoints without any
reverse engineering, lowering the skill threshold for further exploitation.

---

## Summary

The v3.0.39→v4.02.13 transition adds not just more code but qualitatively new attack
surfaces: persistent cloud/VPN egress channels, Docker containers on PLC hardware,
browser-managed filesystem integrity checking, and full OPC UA PKI control. Each module
individually has legitimate operational value; together, they compose a substantially
richer environment for persistent, multi-vector ICS malware. Notably, the same web
interface that WAGO now uses to *defend* the device (AIDE, firewall, certificate
management) is the one that IronSpider's CVE chain can fully compromise—turning every
new security feature into a potential attacker-controlled tool.
