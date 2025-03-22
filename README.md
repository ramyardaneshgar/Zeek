# THM-Writeup-Zeek
Writeup for TryHackMe Zeek Lab -Zeek network traffic analysis and detection engineering toolkit with custom scripts, signatures, and CLI workflows for threat hunting and NSM.

By Ramyar Daneshgar 


## Task 1 – Introduction

The lab begins by introducing **Zeek (formerly Bro)** as a **passive, open-source network traffic analyzer**. Unlike inline IDS/IPS systems such as Snort or Suricata, Zeek is designed to observe traffic and extract rich metadata across protocols and sessions. It does not block traffic but offers scripting capabilities to detect suspicious patterns, making it well-suited for forensic analysis, behavioral monitoring, and threat hunting.

Zeek's value lies in its **event-driven architecture**, which enables the analyst to monitor not just discrete packets but high-level protocol interactions and behaviors across sessions.

---

## Task 2 – Network Security Monitoring and Zeek

This task delineates the differences between **traditional network monitoring** and **Network Security Monitoring (NSM)**.

- **Traditional Monitoring** focuses on asset availability, throughput, and configuration management—tasks typically owned by IT operations.
- **NSM**, by contrast, is focused on visibility into **network anomalies**, **malicious activity**, and **indicators of compromise**. It requires structured traffic logging, inspection of protocol-level interactions, and correlation across sessions.

### Zeek Architecture

Zeek comprises two layers:
1. **Event Engine** – Parses raw traffic and extracts protocol events.
2. **Policy Script Interpreter** – Applies Zeek scripts to evaluate event data, trigger alerts, and generate logs.

I used `zeekctl` to control the Zeek daemon and processed packet captures (pcaps) in standalone mode for forensic replay:
```bash
zeek -C -r sample.pcap
```
This command generated structured logs including connection (`conn.log`), DNS, DHCP, HTTP, and alert files such as `notice.log`.

---

## Task 3 – Zeek Logs

Zeek outputs **over 50 log types** categorized into seven domains: Network, Detection, Files, NetControl, Observations, Diagnostics, and Miscellaneous.

Key concepts:
- **Logs are tab-separated ASCII files**, optimized for parsing and machine processing.
- **Session-level correlation** is made possible through the use of **unique identifiers (UIDs)** assigned to connections.

Example correlation workflow:
1. Identify a suspicious DNS query in `dns.log`.
2. Trace the associated UID to `conn.log` to find source IP and session metadata.
3. Check for alerts in `notice.log` tied to the same UID.

For efficient parsing:
```bash
cat conn.log | zeek-cut uid proto id.orig_h id.resp_h
```

This structured format supports integration with external tools (e.g., SIEMs, Splunk, ELK), but also facilitates standalone forensic workflows via the CLI.

---

## Task 4 – CLI Kung-Fu: Processing Zeek Logs

Given the volume of data Zeek generates, command-line proficiency is essential.

Key tools and techniques:
- **Field extraction**: `cut`, `awk`, `zeek-cut`
- **Filtering**: `grep`, `sed`
- **Counting and sorting**: `sort`, `uniq`, `wc`

Example: Extract all unique HTTP hostnames:
```bash
cat http.log | zeek-cut host | sort | uniq
```

Using `zeek-cut` ensures extraction is based on field names rather than positional assumptions, which is critical when working with evolving log schemas.

---

## Task 5 – Zeek Signatures

Zeek supports **signature-based detection**, similar in concept to Snort but designed for higher-level events and used in conjunction with scripts.

A Zeek `.sig` file includes:
- **Header filters**: Source/destination IP, port, protocol.
- **Content filters**: Payload matching via strings or regular expressions.
- **Actions**: Typically logging to `signatures.log` and optionally triggering scripts.

Example: Detecting the presence of the string “password” in HTTP payloads:
```zeek
signature http-password {
  ip-proto == tcp
  payload /password/i
  event "Cleartext Password Found!"
}
```
Executed via:
```bash
zeek -C -r http.pcap -s http-password.sig
```

While effective for simple detections, signature-based methods in Zeek are generally more powerful when used in tandem with scripting for context-aware detection.

---

## Task 6 – Zeek Scripts: Fundamentals

Zeek's scripting language allows for **event-driven policy enforcement**, enabling analysts to react to high-level protocol events (e.g., new connections, file transfers, signature matches).

Scripts can:
- Define global variables
- Register event handlers
- Log structured data
- Integrate with frameworks

For instance, extracting DHCP hostnames can be scripted with a few lines:
```zeek
event dhcp_message(c: connection, msg: dhcp_msg) {
    if ( msg$host_name != "" )
        print fmt("Hostname: %s", msg$host_name);
}
```

Scripts reside under `/opt/zeek/share/zeek/site/` and are called with:
```bash
zeek -C -r pcap.pcap script.zeek
```

---

## Task 7 – Zeek Scripts with Signatures

In this task, I combined scripts with signatures using the `signature_match` event:
```zeek
event signature_match(s: string) {
    if (s == "ftp-admin") print "Admin login attempt detected.";
}
```

I also explored how Zeek’s **default protocol detection policies** (e.g., FTP brute-force detection) are often more refined than custom rules:
```bash
zeek -C -r ftp.pcap /opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek
```

These scripts produce summary alerts in `notice.log`, with contextual data about login failures, time ranges, and impacted hosts.

---

## Task 8 – Zeek Frameworks

Zeek offers modular frameworks to extend detection and analysis.

### File Framework

Used to hash or extract transferred files:
```zeek
@load policy/frameworks/files/hash-all-files.zeek
@load policy/frameworks/files/extract-all-files.zeek
```

Execution:
```bash
zeek -C -r capture.pcap hash-demo.zeek
```

Hash results appear in `files.log`. File contents are stored in an `extract_files` directory.

### Intel Framework

Supports ingestion of **threat intelligence feeds**, such as domain names, IPs, hashes.

Example intel file (tab-delimited):
```
#fields	indicator	indicator_type	meta.source	meta.desc
malicious-domain.com	Intel::DOMAIN	ZeekIntel	Example Test
```

Script to load:
```zeek
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice
redef Intel::read_files += { "/opt/zeek/intel/zeek_intel.txt" };
```

Execution:
```bash
zeek -C -r case1.pcap intelligence-demo.zeek
```

Results in `intel.log` upon matches.

---

## Task 9 – Zeek Packages

Zeek integrates with **third-party packages** via the **Zeek Package Manager (`zkg`)**.

Installed packages:
```bash
zkg install zeek/cybera/zeek-sniffpass
```

Usage:
```bash
zeek -Cr http.pcap zeek-sniffpass
```

This module logs cleartext password submissions in HTTP POST traffic, similar to the manual signature developed in Task 5, demonstrating how prebuilt packages reduce duplication and speed deployment.

Another example:
```bash
zeek -Cr case1.pcap geoip-conn
```
This enriches `conn.log` with geolocation data (GeoLite2 database), enabling geographic attribution during investigations.

---

## Task 10 – Conclusion

Through this lab, I gained comprehensive view of Zeek's capabilities in traffic analysis, event correlation, and detection engineering.

---

## Final Thoughts and Lessons Learned

1. **Zeek's flexibility** comes from its **event-driven scripting language**, allowing analysts to define highly specific detection logic based on protocol interactions and contextual metadata.

2. **Effective Zeek usage depends on strong command-line proficiency**. While GUI-based tools offer accessibility, CLI tools (e.g., `zeek-cut`, `awk`, `grep`) provide the necessary speed and precision for incident response and forensic workflows.

3. **UID-based session correlation** across logs is essential. Investigations often rely on stitching together events from `conn.log`, `http.log`, `files.log`, and others using shared identifiers.

4. **Frameworks and packages** extend Zeek’s functionality rapidly. Leveraging them allows organizations to integrate threat intel, extract files, or hash content without building custom scripts from scratch.

5. Zeek is **not a replacement for IDS**, but a **complementary tool** that provides deeper inspection, especially valuable in post-compromise investigations, threat hunting, and anomaly detection.

