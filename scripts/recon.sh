#!/bin/bash
# ============================================================
# recon.sh — Week 1 Linux Security Reconnaissance Script
# Author  : [Your Name]
# Purpose : Automated local Linux recon for security auditing
# Usage   : sudo bash recon.sh [--output /path/report.txt]
# ============================================================

OUTPUT="${2:-$HOME/security-lab/evidence/recon-$(date +%Y%m%d-%H%M%S).txt}"
mkdir -p "$(dirname "$OUTPUT")"
exec > >(tee "$OUTPUT") 2>&1

RED='\033[0;31m'; YEL='\033[0;33m'; GRN='\033[0;32m'
CYN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

banner() { echo -e "\n${BOLD}${CYN}========== $1 ==========${NC}"; }
warn()   { echo -e "${YEL}[!] $1${NC}"; }
alert()  { echo -e "${RED}[ALERT] $1${NC}"; }
ok()     { echo -e "${GRN}[OK] $1${NC}"; }

echo -e "${BOLD}recon.sh | $(date) | $(hostname)${NC}"
echo "Output: $OUTPUT"

# ------ SECTION 1: System Identity (Day 1 + 2) ------
banner "SYSTEM IDENTITY"
echo "Hostname  : $(hostname)"
echo "OS        : $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
echo "Kernel    : $(uname -r)"
echo "Arch      : $(uname -m)"
echo "Uptime    : $(uptime -p 2>/dev/null || uptime)"

# ------ SECTION 2: Network Exposure (Day 1) ------
banner "OPEN PORTS + LISTENING SERVICES"
ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null
echo ""
echo "--- Active connections ---"
ss -tunp 2>/dev/null | head -20

# ------ SECTION 3: User Enumeration (Day 5) ------
banner "USER ACCOUNT AUDIT"

echo "--- All loginable accounts ---"
grep -v "nologin\|false\|sync\|halt\|shutdown" /etc/passwd \
  | awk -F: '{print $1, "(UID:"$3, "Shell:"$7}'

echo ""
echo "--- UID-0 accounts (should only be root) ---"
awk -F: '$3==0 {print $1}' /etc/passwd | while read u; do
  [[ "$u" != "root" ]] && alert "Non-root UID-0 account: $u" || ok "Only root has UID 0"
done

echo ""
echo "--- Privileged group memberships ---"
for g in sudo wheel admin docker shadow disk adm; do
  members=$(getent group "$g" 2>/dev/null | cut -d: -f4)
  [[ -n "$members" ]] && warn "Group '$g' members: $members"
done

# ------ SECTION 4: Password Policy (Day 5) ------
banner "PASSWORD + SHADOW AUDIT"
if [[ $EUID -eq 0 ]]; then
  echo "--- Accounts with no password (empty hash) ---"
  awk -F: '($2=="" || $2=="::"){print "[NO PASSWORD] "$1}' /etc/shadow 2>/dev/null
  echo "--- Locked accounts ---"
  awk -F: '$2~/^!/{print "[LOCKED] "$1}' /etc/shadow 2>/dev/null
  echo "--- Hash algorithms in use ---"
  awk -F: 'NF>1 && $2!~/^[!*]/ && $2!="" {print $1": "substr($2,1,3)}' /etc/shadow 2>/dev/null \
    | sed 's/\$1\$/MD5 (WEAK)/;s/\$5\$/SHA-256/;s/\$6\$/SHA-512/;s/\$y\$/yescrypt/'
else
  warn "Run as root to audit /etc/shadow"
fi

# ------ SECTION 5: Sudo Configuration (Day 5) ------
banner "SUDO AUDIT"
echo "--- Current user sudo rights ---"
sudo -l 2>/dev/null || echo "No sudo access for current user"

echo ""
echo "--- NOPASSWD entries (high risk) ---"
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
  | grep -v "^#" && warn "NOPASSWD entries found — check GTFOBins for each binary" \
  || ok "No NOPASSWD entries found"

# ------ SECTION 6: SUID/SGID Binaries (Day 4) ------
banner "SUID / SGID BINARIES"
echo "--- SUID binaries (run as owner, often root) ---"
find / -perm -4000 -type f 2>/dev/null | while read f; do
  owner=$(stat -c '%U' "$f" 2>/dev/null)
  echo "$f  [owner: $owner]"
  [[ "$owner" == "root" ]] && warn "SUID root binary — check GTFOBins: $f"
done

echo ""
echo "--- SGID binaries ---"
find / -perm -2000 -type f 2>/dev/null | head -20

# ------ SECTION 7: Writable Directories (Day 3 + 4) ------
banner "WORLD-WRITABLE LOCATIONS"
echo "--- World-writable directories ---"
find / -writable -type d -not -path "*/proc/*" 2>/dev/null | grep -v "^/sys" | head -20
echo ""
echo "--- Files in /tmp and /dev/shm ---"
find /tmp /dev/shm -type f 2>/dev/null | while read f; do
  warn "File in writable area: $f"
done

# ------ SECTION 8: Recent File Changes (Day 3 + 6) ------
banner "RECENTLY MODIFIED FILES (last 24h)"
find / -mtime -1 -type f \
  -not -path "*/proc/*" \
  -not -path "*/sys/*" \
  2>/dev/null | head -30

# ------ SECTION 9: Log Analysis (Day 6) ------
banner "AUTHENTICATION LOG ANALYSIS"
AUTH="/var/log/auth.log"
if [[ -r "$AUTH" ]]; then
  total_lines=$(wc -l < "$AUTH")
  failed=$(grep -c "Failed password" "$AUTH" 2>/dev/null)
  accepted=$(grep -c "Accepted" "$AUTH" 2>/dev/null)
  echo "Total auth log lines : $total_lines"
  echo "Failed login attempts: $failed"
  echo "Successful logins    : $accepted"

  echo ""
  echo "--- Top 10 IPs by failed attempts ---"
  grep "Failed password" "$AUTH" 2>/dev/null \
    | awk '{print $11}' | sort | uniq -c | sort -rn | head -10

  echo ""
  echo "--- Top targeted usernames ---"
  grep "Failed password" "$AUTH" 2>/dev/null \
    | awk '{print $9}' | sort | uniq -c | sort -rn | head -10

  echo ""
  echo "--- Successful login sources ---"
  grep "Accepted" "$AUTH" 2>/dev/null \
    | awk '{print $11}' | sort | uniq
else
  warn "Cannot read $AUTH — try running as root"
fi

# ------ SECTION 10: Sensitive File Hunt (Day 2 + 3) ------
banner "SENSITIVE FILE DISCOVERY"
echo "--- SSH private keys ---"
find / -name "id_rsa" -o -name "*.pem" -o -name "*.key" 2>/dev/null \
  | grep -v "^/proc" | while read f; do warn "Private key: $f"; done

echo ""
echo "--- Plaintext credentials in common locations ---"
grep -rE "password\s*=\s*['\"]?[^'\" ]{4,}" \
  /etc/ /var/www/ /opt/ 2>/dev/null \
  | grep -v "^Binary" | head -20

echo ""
echo "--- .bash_history files ---"
find /home /root -name ".bash_history" 2>/dev/null | while read f; do
  lines=$(wc -l < "$f" 2>/dev/null)
  warn ".bash_history found: $f ($lines lines)"
done

# ------ SUMMARY ------
banner "SCAN COMPLETE"
echo "Report saved to: $OUTPUT"
echo "Scan time: $(date)"
echo ""
echo "Next steps:"
echo "  1. Check each SUID binary against gtfobins.github.io"
echo "  2. Review all NOPASSWD sudo entries"
echo "  3. Investigate any non-root UID-0 accounts"
echo "  4. Review sensitive files found in Section 10"
