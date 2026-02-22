# Lab Notebook - IronSpider Replication & Extension Study

## Feb 17, 2026 - Day 1

### Objective

Complete a structured overview on the paper, especially on its technical aspects. Answer 6 core questions based on its content.

### Paper

"Compromising Industrial Processes using Web-Based PLC Malware"
Pickren, Shekari, Zonouz, Beyah - NDSS 2024
Paper: [https://dx.doi.org/10.14722/ndss.2024.23049](https://dx.doi.org/10.14722/ndss.2024.23049)

Artifacts: [https://zenodo.org/record/8279954](https://zenodo.org/record/8279954)

### Questions & Answers

#### 1. What did each CVE do?

CVE-2022-45139 is a Cross-Origin Resource Sharing (CORS) misconfiguration, where adding `/x.pdf` at any API endpoint results in the webserver responding with the wildcard "Access-Control-Allow-Origin", allowing it to be called cross-origin. 

CVE-2022-45138 shows how leaving off cookie intentionally and adding "renewSession:true" forces the use of a guest user account, which has access to several APIs.

CVE-2022-45140 shows how "network_config" API allows writing an arbitrary data onto an arbitrary location under root privileges, through "--error-msg-dst" argument.

These three CVEs allow for cross-origin reference, authentication bypass, and arbitrary file upload, allowing for IronSpider to act freely.

#### What is WebVisu and why does it matter?

WebVisu is a GUI provider application licensed by CODESYS. It allows operators to drag and drop different GUI elements onto their HMI (Human-Machine Interface) dashboards. 

If an attacker can manipulate these pre-built GUI elements, and an operator downloads it for using it on their HMI dashboard, it is possible to infect the system with WB PLC malware.  Simply changing the content of transpiled elements or overwriting them was sufficient for this task. The paper used the previously explored CVEs to overwrite WebVisu elements for allowing IronSpider to infiltrate into the system.

#### Why does Service Worker resurrection survive hardware replacement?

Replacement of hardware results in deleting the WB malware installed on PLC. The "resurrection" code in Service Worker on EWS or HMI detects this discrepancy, and simply re-install the malware on the newly installed PLC. 

#### Why did all 4 JS malware detectors fail?

The most likely explanation provided by this paper is that while standard IT-based JS malwares exhibit aggressive behavioural indicators (such as mining cryptocurrency in WebAssembly, using off-the-shelf exploit kits, etc), IronSpider simply utilises the DOM interface as intended. Since IronSpider stays conservative and passive, the detectors falsely categorised it as benign.

#### What are the paper's stated limitations?

One obvious limitation is that WB malware is only applicable to modern industrial control systems (ICSs) using embedded web servers. It cannot affect legacy ICS. 

Moreover, the effectiveness of WB malware is directly influenced by how capable the internal web API is for a given ICS. If the ICS only runs a limited set of APIs for controlling the physical components of the system, WB malware will not be as effective.

Also, since some of the APIs available inside an ICS can only be accessible by certain users, WB malware's capability is limited by the victim user's permissions and capabilities.

Finally, display spoofing is not a viable attack for systems which use non-web using traditional ICS protocols such as legacy data historians or SIS.

This project aims at improving the defender's capability of detecting a potential WB malware within its modern ICS system, assuming that the system uses an embedded web server.

#### What would a defender do to stop the attack?

The defender can conduct domain sandboxing, where they host user-defined programs on a separate domain. Since the domain is different from that of the PLC vendors', this can prevent potentially malicious JavaScript codes from affecting the PLC system.

Limiting the communication between private Intranet and public Internet can be an option which addresses the potential threat of WB malwares on a fundamental level. 

Also, implementing CSP with *confidentiality* directive can be used to prevent exfiltration. This was proposed by Firefox in 2012, then shelved. 

Read-only CDN for vendor-provided PLC can be used to prevent them from being overwritten. Also, using CSP directives for `src-script` can help. However, this immensely reduces practicality of the system design, requiring substantial front-end restructure. 

PLC-configured web app firewalls (WAPs) can also be used to inspect non-web protocols such as SNMP, CIP, and Modbus. This measure can add latency to the system.

### Artifacts Downloaded

For Day 1, I conducted a brief overview on some of the exploit programs in the provided artifacts. 

#### `AB_EXPLOIT/exploit.py`

This uses cross-channel scripting (XCS) to inject IronSpider into the victim MicroLogix 1100 & 1400 PLC. 

#### `WAGO_EXPLOIT/`exploit.html`

This uses the CVE chain discussed in the paper (CORS misconfiguration, authentication bypass, and arbitrary file injection) to inject WB malware.

#### `Resurrection/sw.js`

This demonstrates how to bypass limitations of a Service Worker, by waiting for a legitimate fetch request for a JS file and replacing it with `event.respondWith`.

Service Workers do not have access to the DOM structure, localStorage, or synchronous APIs. However, they can mock the response to a legitimate `fetch` request with loading WB malware, which is then loaded onto main page. The loaded WB malware then has access to the full DOM structure, localStorage, and so on.

## Feb 18, 2026 - Day 2

### Environment Setup

- OpenPLC: installed on my Arch Linux environment, at localhost:8080
    - Specifying the path to find modbus was an issue, resolved by running `export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH`.
- Node.js: for running a local HTTPS server for Service Worker resurrection
- mkcert: for providing a locally-trusted HTTPS certificate, allowing Service Worker to be run
- mitmproxy: for implementing detection mechanism for IronSpider or relevant WB malware

### OpenPLC API Map

#### /login

This is the first landing page. It accepts `openplc` as both username and password for navigating to `/dashboard`.
![alt text](image.png)

#### /dashboard

- runtime_logs endpoint: this page runs `GET /runtime_logs HTTP/1.1` every second to reload the runtime log.
![alt text](image-1.png)

#### /programs

- `POST /upload-program HTTP/1.1` endpoint for uploading a new `.st` program to OpenPLC
- `GET /programs?list_all=1 HTTP/1.1` to list all the uploaded `.st` programs
![alt text](image-2.png)

#### /monitoring

- While running a program, this page sends `GET /monitor-update?mb_port=502 HTTP/1.1` request every `Refresh Rate` set by the user.
![alt text](image-3.png)

### Key Observations

On Dashboard and Monitoring pages, OpenPLC repeatedly sends requests to update to the latest state for the system. 

The user can upload `.st` files and compile them, running them on the PLC provided by pressing the`Start PLC` button.

### Water Pump Program

I added Water Pump Program under `E2-openplc-demo/`, and managed to upload it onto OpenPLC. Running it does not show any monitoring variables, so this will be the task for tomorrow.

... I managed to fix the bug today! The core problem was inside `webserver/monitoring.py`, where `parse_st` function simply rejected any line of code containing comment characters:`(`, `)`. My original code contained `AT` variables (variables that can be accessed in the monitoring interface) with these comments, making the parser to ignore those declarations completely. Once I removed the comments and the parser correctly identified the variables, I could see them on OpenPLC's `/monitoring` endpoint. 

## Day 3: Feb 19, 2026

### Brief Overview on the WAGO Firmwares

I downloaded the WAGO firmwares that were analysed in the paper's E1 section, and extracted them with `binwalk`. The versions I downloaded are the same as those from the paper: v03.0.39 and v04.02.13. After finding out that the extracted filesystems are `ext3` type, I mounted them on `/mnt/wago-old` and `/mnt/wago-new` respectively, to view web contents and their paths inside the filesystems. 

```bash
# Search for web files
find /mnt/wago-old -name "*.js" -type f 2>/dev/null | head -20
find /mnt/wago-old -name "*.php" -type f 2>/dev/null | head -20

# Check common web locations
ls -la /mnt/wago-old/var/www/
ls -la /mnt/wago-old/home/
ls -la /mnt/wago-old/usr/share/
```
```bash
/mnt/wago-old/var/www/ws/eWS.js
/mnt/wago-old/var/www/wbm/js/dns_server.js
/mnt/wago-old/var/www/wbm/js/modem.js
/mnt/wago-old/var/www/wbm/js/tftp.js
/mnt/wago-old/var/www/wbm/js/clock.js
/...
/mnt/wago-old/var/www/wbm/page_elements/bacnet_general_configuration.inc.php
/mnt/wago-old/var/www/wbm/page_elements/network_services.inc.php
/mnt/wago-old/var/www/wbm/page_elements/system_partition.inc.php
/mnt/wago-old/var/www/wbm/page_elements/firewall_general_configuration.inc.php
/mnt/wago-old/var/www/wbm/page_elements/service_interface.inc.php
total 6
drwxr-xr-x  5 root root 1024 May  8  2019 .
...
drwxr-xr-x  2 root root   1024 May  7  2019 locale
drwxr-xr-x  3 root root   1024 May  7  2019 opkg
drwxr-xr-x  3 root root   1024 May  7  2019 snmp
drwxr-xr-x  8 root root   1024 May  7  2019 terminfo
drwxr-xr-x  2 root root   1024 May  7  2019 udhcpc
-rw-r--r--  1 root root 502948 May  7  2019 usb.ids
drwxr-xr-x  2 root root   1024 May  7  2019 zoneinfo
```
```bash
# Search for web files
find /mnt/wago-new -name "*.js" -type f 2>/dev/null | head -20
find /mnt/wago-new -name "*.php" -type f 2>/dev/null | head -20

# Check common web locations
ls -la /mnt/wago-new/var/www/
ls -la /mnt/wago-new/home/
ls -la /mnt/wago-new/usr/share/
```
```bash
/mnt/wago-new/var/www/openapi/redoc.standalone.js
/mnt/wago-new/var/www/ws/eWS.js
/mnt/wago-new/var/www/wbm/plugins/wbm-statusplcswitch/statusplcswitch.js
/mnt/wago-new/var/www/wbm/plugins/wbm-profibus/profibus.js
/mnt/wago-new/var/www/wbm/plugins/wbm-profibus/platform/pfcXXX/parameter/transforms/get-profibus-dp-slave-ssa-user-address.js
/mnt/wago-new/var/www/wbm/plugins/wbm-user/user.js
/...
/mnt/wago-new/var/www/wbm/php/file_transfer/prepare_transfer.php
/mnt/wago-new/var/www/wbm/php/file_transfer/file_transfer.inc.php
/mnt/wago-new/var/www/wbm/php/file_transfer/response/response.inc.php
/mnt/wago-new/var/www/wbm/php/file_transfer/cleanup_transfer.php
total 20
drwxr-xr-x  5 root root 4096 Mar 23  2023 .
drwxr-xr-x 11 root root 4096 Mar 23  2023 ..
...
drwxr-xr-x  2 root root   4096 Mar 23  2023 zoneinfo
```
### Replication of E1: WAGO 750-8XXX WBM Application Code Base study

After verifying that the firmwares contain web-based contents (`.js`, `.php`), I looked at the paper artifacts on *zenodo.org* to imitate the paper's analysis.

Following the instructions on `README.me` for `WBM_Code_Study`, I managed to replicate the results from the paper. I had to rebuild the Docker image and place it in `WBM_Code_Study/prebuilt/`, since my machine is based on x86_64 architecture:

```bash
docker build -t artifact ./docker_artifact/
docker save 166bd4f275c6 > ./prebuilt/docker_artifact.tar
```
The result is shown below:

```bash
 * Loading Docker Image...
 * Loading Old FW...
    > Old firmware contained 13,188 total SLOC (12,868 JS; 320 PHP) and an aggregate cyclomatic complexity score of 4,529 (2,922 JS; 1,607 PHP)
 * Loading New FW...
    > New firmware contained 39,007 total SLOC (38,444 JS; 563 PHP) and an aggregate cyclomatic complexity score of 11,974 (9,294 JS; 2,680 PHP)
    > This data shows that over the past several years, the web application codebase has grown by over 195% and increased in complexity by over 164%.
 * Removing Docker Image...
 * Done
```
## Day 4: Feb 20, 2026

Today, I read two research papers that were cited by the IronSpider paper, so that I can gain more background knowledge and deeper understanding in ICS and attacks against PLCs.

### Hey, My Malware Knows Physics! Attacking PLCs with Physical Model Aware Rootkit 

This paper explores a PLC malware called *Harvey*, which sits in the firmware of a PLC to control the physical behaviours of the underlying ICS in the attacker's favour while remaining 'stealthy' and preventing its adverse impact from getting noticed by human operators. 

*Harvey* is effective in that it can remain undetected within an ICS and hence can cause damage on it for a prolonged period of time. However, it requires the attackers to have thorough understanding of the firmware used. The paper mentions reverse-engineering the target firmware. IronSpider addresses this issue by controlling the UI on browser-based HMIs, which does not require attackers to fully comprehend the inner mechanisms of the system.

### Exposed Infrastructures: Discovery, Attacks and Remediation of Insecure ICS Remote Management Devices

This paper describes how Internet-facing remote management devices are exposed to unintended users. This opened up possibilities for attacks against critical ICS such as water gates. 

At the time of the paper, many of the ICSs that operated web-based remote management devices had vulnerabilities such as no authentication and weak passwords for their remote access points. 

Moreover, the paper set up an intentionally vulnerable remote management device in order to analyse how attractive it is for potential attackers. This revealed that there are potential attackers who are willing to explore the endpoints of the device and even conduct attacks against it.

IronSpider sets itself as an example against a typical Internet-facing remote management device, as it injects its code via the access to an ICS on the Internet. It then places itself in the rendering browser to gain access and control to the underlying ICS.

## Day 5: Feb 21, 2026

### SLOC & Complexity Analysis on 2 intermediate firmwares

To extend the paper's analysis for E1, I decided to run `WBM_Code_Study/prebuilt/automation.py` against 2 intermediate firmwares betwen v3.0.39 and v4.02.13. This aims at building a more extensive timeline of growth in web application codebase in these firmwares.

I chose the following intermediate firmwares for analysis:
- v3.01.07 (Jul 2019)
- v3.09.04 (Mar 2022)

I created a new automation program (`automation_ext.py`) in Python, using the original `automation.py` as the template. This file can be found in `E1-firmware-analysis/automation_ext.py`.

The result is shown below:
```bash
 * Loading Docker Image...
 * Loading v3.1.7..
    > v3.1.7 firmware contained 13,472 total SLOC (13,150 JS; 322 PHP) and an aggregate cyclomatic complexity score of 4,574 (2,964 JS; 1,610 PHP)
 * Loading v3.09.04...
    > v3.09.04 contained 36,544 total SLOC (35,994 JS; 550 PHP) and an aggregate cyclomatic complexity score of 11,379 (8,764 JS; 2,615 PHP)
    > This data shows that from v3.1.7 to v3.09.04, the web application codebase has grown by over 171% and increased in complexity by over 148%.
 * Removing Docker Image...
 * Done
```
The result confirmed that there had been a consistent increase in web-related contents in the firmwares over the given timeframe (from v3.0.39 to v4.02.13). It shows that the growth of web application codebase had taken place incrementally, and was not a sudden 'jump'. 

For the upgrade between v3.0.39 and v3.1.7, the total SLOC increased from 13,188(12,868 JS, 320 PHP) to 13,472 total SLOC(13,150 JS, 322 PHP). The aggregate cyclomatic complexity score also increased from 4,529 to 4,574. In addition, the upgrade between v3.09.04 and v4.02.13 showed an increase in total SLOC from 36,544(35,994 JS, 550 PHP) to 39,007 total SLOC(38,444 JS, 563 PHP), with the cyclomatic complexity score also increasing from 11,379 to 11,974.

### Noteworthy changes in web-related content during firmware upgrades

I strived to extend the paper's work further by moving from a quantitative analysis (SLOC, complexity) to a qualitative one. The question is: *what kind of* functionality was added between v3.0.39 and v4.02.13?, I looked for any noteworthy change in JS files between the v3.0.39 and v4.02.13 firmwares, that could have increased the area of attack surface for web applications codebase.

### JS File Diff — Qualitative Functionality Analysis

**Method**: Wrote `E1-firmware-analysis/js_diff.py` to enumerate all `.js` files from both mounted firmware roots (`/mnt/wago-old` for v3.0.39, `/mnt/wago-new` for v4.02.13), compute stem-level diff (accounting for the flat→plugin architecture change), categorize new files by functional domain, and extract API endpoint strings from new plugin files.

**Output files**:
- `E1-firmware-analysis/js_diff.json` — structured diff with categories and snippets
- [`E1-firmware-analysis/js_diff_summary.txt`](../E1-firmware-analysis/js_diff_summary.txt) — human-readable summary
- `E1-firmware-analysis/js_diff_report.md` — a qualitative analysis

**Key findings**:

| Category | New Files | Notable Additions |
|---|---|---|
| Core Framework | 18 | `pfc.js` plugin loader replaces jQuery `page_buildup.js` |
| Security/Auth | 12 | `wbm-aide` (AIDE IDS), `wbm-firewall` (iptables+ebtables), `wbm-certificate-uploads` |
| Industrial Protocols | 12 | OPC UA PKI (8 cert transforms), WDA unauthenticated scan toggle |
| Monitoring | 12 | Pcap logging (`pcaplog.maxfilesize`), runtime task list, LED/switch status |
| Cloud/Remote | 7 | `wbm-cloud-connectivity` (Azure/AWS/IBM/SAP/MQTT), `wbm-openvpn-ipsec`, `wbm-modem-ng` |
| Container/Infra | 4 | `wbm-docker`, `wbm-ipk-uploads`, `wbm-package-server` |
| API Docs | 1 | `openapi/redoc.standalone.js` — self-describing REST API on-device |

Every new "security" feature (AIDE, firewall, certificate management) is managed through the same WBM web interface that IronSpider's CVE chain can fully compromise, potentially causing new defensive capabilities to become attacker-controllable tools. Meanwhile, Docker on PLCs and persistent MQTT cloud channels represent qualitatively new ICS attack surface, which can only be found in v4.02.13.

## Day 6: Feb 22, 2026

Today, I looked into Service Workers in more detail. 

Service Worker is a Javascript code that runs on your browser to perform the following tasks: offline rendering, push notifications, background sync, and network interception. It caches HTML, CSS, or even API responses for providing the basic experience of a web application when offline.

Service Worker's lifecycle has the following structure:
- Registration: A Service Worker is initiated with `navigator.serviceWorker.register('/sw.js')`.
- Installation: The Service Worker caches essential static assets.
- Waiting: If there is an old version controlling open tabs, the new Service Worker waits unless `self.skipWaiting()` is called.
- Activation: It is activated, cleans up old cache.
- Controlling: Now, the Service Worker controls the tabs within its scope.
- Idle/Terminated: The browser can terminate the Service Worker after a period of inactivity. When events like fetch, push, or sync occur, it will be reactivated.

For WB malwares against PLC, a Service Worker registered by the malware can survive complete deletion of the malware from the ICS, checks the malware's presence periodically, and infect the cleansed system again by downloading the malware in the background.