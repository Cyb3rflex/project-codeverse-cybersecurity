## Zonetransfer.me
Zonetransfer.me is a training domain intentionally vulnerable to DNS zone transfer. That means the students can safely practice real-world enumeration and attack flow on it.

Here’s a clean, real-world style workflow you can give both Red Team and Blue Team, simple enough for students but realistic enough for industry.

## RED TEAM WORKFLOW (Pentest steps)

Direct, practical, and run-ready in Termux/Kali.

> 1. Reconnaissance – DNS Enumeration

This domain is deliberately misconfigured, so the first thing to try is zone transfer.

Run:
```bash
host zonetransfer.me
host -t ns zonetransfer.me
```

Then try pulling the zone:
```bash
dig axfr zonetransfer.me @nsztm1.digi.ninja
dig axfr zonetransfer.me @nsztm2.digi.ninja
```

A successful zone transfer reveals:

• Subdomains
• Internal systems
• Email servers
• TXT records (sometimes with credentials)
• Staging servers
• Backup servers
• Test environments

This is exactly how attackers pivot: find hidden assets that people forget exist.

> 2. Map the Attack Surface

Once the subdomains are exposed, enumerate each one:
```bash
nmap -sV -p- <IP>
```

Or:
```bash
whatweb <subdomain>
```

Students should look for:

• Unpatched services
• Weak SSH services
• Directory listings
• Default credentials
• Exposed web apps
• Open ports that shouldn’t be public

> 3. Web Attack Simulation

Pick any web app from the zone transfer results.

Test for:

• SQL Injection
• XSS
• Directory traversal
• File upload bypass
• Weak authentication
• Misconfigurations
• Outdated CMS/plugins

Tools you can use:
```bash
nikto -h http://<subdomain>
```

Or manually browsing and fuzzing:
```bash
ffuf -u https://<subdomain>/FUZZ -w /usr/share/wordlists/dirb/common.txt
```
> 4. Credential Attacks (Safe Simulation)

If zone transfer reveals test emails or usernames, you can simulate:

• Password spraying
• Weak password checks

Example spraying test:
```bash
hydra -l admin -P passwords.txt ssh://<IP>
```
> 5. Reporting

Red team must document:

• Vulnerability
• How they found it
• Impact
• How to fix it

This is the most important part professionally.

## BLUE TEAM WORKFLOW (Defensive steps)
> 1. Prevent DNS Zone Transfer

- Core fix: disable AXFR.

 **In BIND:**

`allow-transfer { none; };`


Or restrict to internal IPs only.

This one fix blocks the entire Red Team chain because they lose all internal asset discovery.

> 2. Network Monitoring

Since they’re all using the same MiFi, the Blue Team can:

• Capture traffic with Wireshark
• Identify DNS AXFR attempts
• Detect Nmap fingerprints
• Detect HTTP fuzzing (ffuf, gobuster)
• Identify abnormal parallel requests

# Blue team should learn:

- DNS queries = normal

- AXFR queries = suspicious

- Hundreds of GET/HEAD requests = fuzzing

- Port scans = recon activity

> 3. Hardening

- For each asset discovered by Red Team, Blue Team should know the defense:

• Disable unnecessary open ports
• Use firewalls (UFW/IPTables)
• Keep services updated
• Disable directory listing
• Enforce strong passwords
• Enable MFA
• Rate-limit login attempts
• Disable default credentials

> 4. Logging & Incident Response

• Web server logs (Apache/Nginx access.log)
• SSH logs (/var/log/auth.log)
• DNS logs
• Alerts for multiple failed logins
• Alerts for port scanning

- Incident response example:

- Detect suspicious scan

- Confirm IP

- Block IP temporarily

- Check logs for damage

- Patch the weak point

> 5. Reporting

Blue Team must document:

• Attack detected
• How they detected it
• What was vulnerable
• How they defended
• Remaining gaps

This mirrors real SOC work.
