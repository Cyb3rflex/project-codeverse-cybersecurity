**Project CodeVerse: Red Team / Blue Team Exercise**

This repository includes an instructor-ready lab for a simulated penetration test and defense exercise. The README below contains role assignments, scenario setup, tool commands, grading rubric, and full report templates for both Red and Blue teams.

**Role Assignment Sheet**

- **Group A – Red Team (Attackers)**
  - Team A1 (Red Team 1 – 5 students)
    - **Attacker Lead:** Coordinates attack workflow, approves tools, manages timeline.
    - **Recon Analyst:** Performs OSINT, subdomain discovery, directory enumeration.
    - **Scanner/Enumeration Specialist:** Runs vulnerability scans, maps endpoints.
    - **Exploit Handler:** Tests vulnerabilities, attempts exploitation ethically.
    - **Documentation & Evidence Analyst:** Records screenshots, notes, payloads, results.
  - Team A2 (Red Team 2 – 5 students)
    - Attacker Lead
    - Recon Analyst
    - Scanner/Enumeration Specialist
    - Exploit Handler
    - Documentation & Evidence Analyst

- **Group B – Blue Team (Defenders)**
  - Team B1 (Blue Team 1 – 5 students)
    - **Defense Lead:** Coordinates defensive measures and strategy.
    - **SOC Analyst:** Monitors logs (web server logs, access logs).
    - **Incident Responder:** Reacts to detected attacks, isolates suspicious IPs.
    - **Traffic Monitor:** Uses Wireshark & firewall tools to detect anomalies.
    - **Documentation & Evidence Analyst:** Logs incidents and defensive actions.
  - Team B2 (Blue Team 2 – 4 students)
    - Defense Lead
    - SOC Analyst
    - Incident Responder
    - Traffic Monitor

**Penetration Testing Scenario Setup**

- **Scenario Title:** Operation CodeVerse Breach — Simulated Attack & Defense Exercise
- **Environment:** Controlled, permission-granted web application (locally hosted or internal/online lab).
- **Prereqs:** Logging enabled (NGINX/Apache access logs, app error logs), dummy test accounts, intentionally-planted low-risk vulnerabilities.
- **Example planted weaknesses:** Weak login, unvalidated inputs, exposed directories, debug mode open, weak admin password, no rate-limiting, robots.txt paths.

**Objectives**
- **Red Team:** Perform structured pentest on the CodeVerse test site, discover and safely exploit vulnerabilities, collect proof, and document findings. No destructive attacks or DoS.
- **Blue Team:** Detect attacks in real time using logs and tools, simulate blocks, document incidents, and recommend/plan patches.

**Rules of Engagement (ROE)**
- Only use approved tools.
- No attacks outside the given domain/IP.
- Red Team must record every action and produce evidence.
- Blue Team cannot shut down the server — only simulate blocking actions.
- Both sides must submit final reports.

**Tools + Commands + How To Use Them**

**A. RED TEAM TOOLSET (Attackers)**

1) Reconnaissance
- **whois** — Check domain ownership and info:
  ```powershell
  whois targetsite.com
  ```
- **nslookup** — DNS lookup:
  ```powershell
  nslookup targetsite.com
  ```
- **dig** — Detailed DNS records:
  ```powershell
  dig targetsite.com ANY
  ```
- **subfinder** (if installed) — Subdomain discovery:
  ```powershell
  subfinder -d targetsite.com
  ```

2) Enumeration & Scanning
- **Nmap** — Basic port scan:
  ```powershell
  nmap targetsite.com
  ```
- Service & version detection:
  ```powershell
  nmap -sV targetsite.com
  ```
- Aggressive scan (safe for labs):
  ```powershell
  nmap -A targetsite.com
  ```
- **Directory brute-force** (Gobuster):
  ```powershell
  gobuster dir -u https://targetsite.com -w /usr/share/wordlists/dirb/common.txt
  ```
- **ffuf** alternative:
  ```powershell
  ffuf -u https://targetsite.com/FUZZ -w wordlist.txt
  ```

3) Web Vulnerability Testing
- **Burp Suite Community** — manual proxy/intercept testing.
  - Open Burp, set browser proxy to `127.0.0.1:8080`.
  - Intercept requests and modify inputs to test for SQLi, XSS, broken authentication.
  - Manual SQLi examples to test (non-destructive):
    - `' OR 1=1 --`
    - `admin' --`
  - Manual XSS test:
    - `<script>alert(1)</script>`

4) Exploitation (ethical, constrained)
- Try weak passwords and structured payloads.
- Avoid destructive commands; document all actions.
- Example bypass test: `\' OR ''='` (record and validate results).

5) Documentation
- For every test record:
  - **URL tested**, **payload used**, **expected vs actual**, and screenshots.

**B. BLUE TEAM TOOLSET (Defenders)**

1) Log Monitoring
- Check webserver logs:
  ```powershell
  tail -f /var/log/nginx/access.log
  # or
  tail -f /var/log/apache2/access.log
  ```
- Watch for repeated requests, suspicious endpoints (`/admin`, `/login`, `/config`, `/backup`) and strange parameters like `?id=' OR`.

2) Wireshark
- Useful filters:
  - Suspicious HTTP requests: `http.request`
  - SQLi-like patterns: `http contains "' OR"`
  - Traffic from one attacker: `ip.addr == 192.168.1.44`

3) Incident Response Steps
- Identify attacker IP, check request frequency/type, document timestamps, and simulate blocking (record the action).

4) SOC Analysis
- Look for many failed logins, high 404 rates, access to hidden files, or unusual patterns.

**Grading Rubric (Team + Individual)**

- **Team-Based Grading (60%) — Red Team (60 marks)**
  - Recon & Enumeration: 15 marks — quality of recon, tool usage, discovered endpoints
  - Vulnerability Identification: 15 marks — correct interpretation, avoid false positives
  - Exploitation Attempts: 15 marks — safe, structured, documented PoCs
  - Team Coordination & Workflow: 5 marks
  - Final Report Quality: 10 marks — structure, evidence, mitigations

- **Team-Based Grading (60%) — Blue Team (60 marks)**
  - Log Monitoring & Detection: 15 marks
  - Incident Response Actions: 15 marks
  - Traffic Analysis: 10 marks
  - Team Coordination: 5 marks
  - Final Defense Report: 15 marks

- **Individual Grading (40%)**
  - Participation & Involvement: 10 marks
  - Role Performance: 15 marks
  - Technical Skill Demonstration: 10 marks
  - Professional Conduct & Documentation: 5 marks

**Full Report Template — Red Team**

RED TEAM – PENETRATION TEST REPORT

- Project Title: Operation CodeVerse Breach – Red Team Assessment
- Team: A1 / A2
- Members: (Insert names)
- Date: (Insert)

1. Executive Summary — Brief overview of vulnerabilities and key findings.
2. Scope of Testing — Target domain/IP, allowed attack surface, permitted tools, limitations.
3. Methodology — Recon → Scanning → Enumeration → Vulnerability Testing → Exploitation → Documentation.
4. Reconnaissance Results — Tools used and findings (whois, dig, nslookup, subdomains, public directories). Include screenshots.
5. Scanning & Enumeration — Nmap/Gobuster findings, open ports, versions, directories. Include screenshots.
6. Vulnerability Identification — List vulnerabilities and attach evidence.
7. Exploitation Attempts — Payloads, outcomes, PoC screenshots.
8. Risk Rating — Classify Low / Medium / High.
9. Mitigation Recommendations — Concrete fixes.
10. Conclusion — Security posture summary.

**Full Report Template — Blue Team**

BLUE TEAM – DEFENSE & INCIDENT RESPONSE REPORT

- Project Title: Operation CodeVerse Breach – Blue Team Defense Report
- Team: B1 / B2
- Members: (Insert names)
- Date: (Insert)

1. Executive Summary — Summary of attacks detected and response.
2. Monitoring Setup — Tools and configuration used for monitoring.
3. Attack Detection Log — Observed attacks with timestamps and attacker IPs.
4. Traffic Analysis (Wireshark) — Filters and findings.
5. Incident Response Actions — Observations, analyses, simulated actions, and evidence.
6. System Weaknesses Identified — Items found during monitoring.
7. Mitigation Recommendations — Suggested fixes.
8. Final Assessment — Overall evaluation of impact and defense performance.

**Usage Notes & Instructor Tips**
- Ensure all participants have signed lab consent and understand ROE.
- Prepare a short demo run to show safe testing and documentation expectations.
- Provide students with a checklist to record every action and a common evidence folder.
