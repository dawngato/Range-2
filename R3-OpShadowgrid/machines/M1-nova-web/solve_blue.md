# 🔵 Blue Team — M1: nova-web Detection Guide

**Challenge:** LFI + Apache Log Poisoning  
**Log Sources:** `/var/log/novatech_access.log`, `/var/log/apache2/error.log`

**Validated M1 address in this session:** `10.0.2.15`. The screenshots below are terminal captures from the live M1 instance.

---

## What to Look For

### 1. LFI Attempts in Access Log

```bash
grep -E "page=(/etc|/var|/proc|php://|%2Fetc%2F|%2Fvar%2F|php%3A%2F%2F)" /var/log/novatech_access.log | tail -n 8
```

![LFI indicators in the access log](screenshots/m1_blue_01_lfi_log.png)

Apache records URL-encoded query strings, so the `%2F...` alternatives are required when searching the raw access log.

Indicators:
- `?page=/etc/passwd` — direct file read attempt
- `?page=php://filter/...` — PHP wrapper based LFI
- `?page=/var/log/...` — log poisoning setup

### 2. PHP Code in User-Agent

```bash
grep -F "<?php" /var/log/novatech_access.log | tail -n 3
grep -Ei "system|exec|passthru|shell_exec" /var/log/novatech_access.log | tail -n 3
```

![PHP payload in the User-Agent](screenshots/m1_blue_02_php_ua.png)

![Command-execution function name in the User-Agent](screenshots/m1_blue_02_exec_ua.png)

A User-Agent containing `<?php system($_GET['cmd']); ?>` is the definitive
log poisoning indicator.

### 3. RCE Command Execution

```bash
grep -E "cmd=(id|whoami|cat|ls|bash|nc|cat\+)" /var/log/novatech_access.log | tail -n 8
```

![RCE commands in the access log](screenshots/m1_blue_03_rce_log.png)

### 4. Timeline Correlation

Build a timeline:
1. First `?page=/var/log/novatech_access.log` request (read probe)
2. Request with malicious User-Agent (injection)
3. Second `?page=/var/log/novatech_access.log&cmd=...` (execution)

```bash
grep -n -E "page=.*(passwd|novatech_access|apache2)|cmd=" /var/log/novatech_access.log | tail -n 6
```

![Correlated LFI-to-RCE timeline](screenshots/m1_blue_04_timeline.png)

### 5. Shell Process from Apache (SIEM / Auditd)

Run the audit query on the M1 host after auditd has been enabled. This host
requires the audit log to be selected explicitly with `--input`:
```bash
sudo ausearch --input /var/log/audit/audit.log -c "bash" --start today | grep "uid=33" || echo "No uid=33 bash audit events found"
```

![Auditd bash query result](screenshots/m1_blue_05_audit_check.png)

The command ran against the live audit log and returned `comm="bash"` records
with `uid=33`, `gid=33`, and `exe="/usr/bin/bash"`, confirming a shell launched
under the Apache/www-data account.

---

## Remediation

- Never pass user input directly to `include()` or `require()`
- Use an allowlist for valid page names: `$allowed = ['home','about','news','contact']`
- Restrict Apache log file permissions: `chmod 640 /var/log/novatech_access.log`
- Deploy a WAF rule blocking `../`, `php://`, `/etc/`, `/var/log/` in GET parameters
- Enable PHP's `open_basedir` restriction in `php.ini`

Remediation commands are not executed during evidence capture because they change the host configuration; the screenshots above cover the observable detection commands.
