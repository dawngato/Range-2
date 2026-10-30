# 🔵 Blue Team — M2: nova-ftpvault Detection Guide

**Challenge:** Anonymous FTP  
**Log Source:** `/var/log/vsftpd.log`

**Validated M2 address for this deployment:** `10.0.2.15`

---

## What to Look For

### 1. Anonymous Login Events

The `vsftpd` log format records this as `OK LOGIN` with `anon_password`, rather than the literal string `ANONYMOUS LOGIN`. The first command below is the working equivalent:

```bash
sudo grep -E 'OK LOGIN|anon_password' /var/log/vsftpd.log
```

![Anonymous login records](screenshots/m2_blue_01_login.png)

```bash
sudo grep "anonymous" /var/log/vsftpd.log
```

![Anonymous user records](screenshots/m2_blue_01_anon_user.png)

Every anonymous login will show source IP, timestamp, and authenticated user ("anonymous").

### 2. File Download Events

```bash
sudo grep "OK DOWNLOAD" /var/log/vsftpd.log
```

![FTP download records](screenshots/m2_blue_02_download.png)

```bash
sudo grep -E 'staff_handover\.txt|flag2\.txt' /var/log/vsftpd.log
```

![Sensitive file download records](screenshots/m2_blue_02_files.png)

A download of `staff_handover.txt` is the critical indicator — this file contains credentials.

### 3. Correlate with M3 Auth Events

After FTP download, check M3's auth.log for SSH login from the same source IP within a short window. Run this on M3 after it is provisioned and the SSH pivot is available:

```bash
sudo grep -E 'Accepted password|session opened|devops' /var/log/auth.log
```

M3 was not provisioned on this combined M1/M2 host, so this correlation command was not run locally.

---

## Remediation

- Set `anonymous_enable=NO` in `/etc/vsftpd.conf` immediately
- Never store credentials in plaintext on shared file systems
- Rotate all credentials exposed via FTP immediately
- Use named FTP accounts with logging enabled
- Consider replacing FTP with SFTP (SSH-based)
