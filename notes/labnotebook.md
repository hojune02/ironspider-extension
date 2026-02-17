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