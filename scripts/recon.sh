#!/bin/bash

# recon.sh - Local Linux Security Recon Script

OUTPUT="$HOME/security-lab/evidence/recon-$(date +%Y%m%d-%H%M%S).txt"

if [[ "$1" == "--output" && -n "$2" ]]; then
OUTPUT="$2"
fi

mkdir -p "$(dirname "$OUTPUT")"
exec > >(tee "$OUTPUT") 2>&1

RED='\033[0;31m'
YEL='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

banner() { echo -e "\n${BOLD}${CYN}========== $1 ==========${NC}"; }
warn()   { echo -e "${YEL}[!] $1${NC}"; }
alert()  { echo -e "${RED}[ALERT] $1${NC}"; }
ok()     { echo -e "${GRN}[OK] $1${NC}"; }

echo -e "${BOLD}recon.sh | $(date) | $(hostname)${NC}"
echo "Output: $OUTPUT"

banner "SYSTEM IDENTITY"
echo "Hostname : $(hostname)"
echo "Kernel   : $(uname -r)"
echo "Arch     : $(uname -m)"
echo "Uptime   : $(uptime -p 2>/dev/null || uptime)"

banner "NETWORK"
ss -tuln 2>/dev/null

echo
echo "--- Active Connections ---"
ss -tunp 2>/dev/null | head -20

banner "USER ACCOUNTS"

grep -v "nologin|false|sync|halt|shutdown" /etc/passwd 
| awk -F: '{print $1,"UID="$3,"SHELL="$7}'

echo
echo "--- UID 0 Accounts ---"
awk -F: '$3==0 {print $1}' /etc/passwd

banner "PRIVILEGED GROUPS"

for g in sudo wheel admin docker shadow disk adm; do
members=$(getent group "$g" 2>/dev/null | cut -d: -f4)
[[ -n "$members" ]] && echo "$g : $members"
done

banner "PASSWORD AUDIT"

if [[ $EUID -eq 0 ]]; then
awk -F: '($2=="" || $2=="::"){print "[NO PASSWORD] "$1}' /etc/shadow
else
warn "Run as root to inspect /etc/shadow"
fi

banner "SUDO"

sudo -l 2>/dev/null || echo "No sudo rights"

echo
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null

banner "SUID BINARIES"

find / -perm -4000 -type f 2>/dev/null

banner "SGID BINARIES"

find / -perm -2000 -type f 2>/dev/null | head -50

banner "WORLD WRITABLE DIRECTORIES"

find / -writable -type d 
-not -path "/proc/*" 
-not -path "/sys/*" 
2>/dev/null | head -50

banner "RECENT FILE CHANGES"

find / -mtime -1 -type f 
-not -path "/proc/*" 
-not -path "/sys/*" 
2>/dev/null | head -50

banner "AUTH LOG REVIEW"

if [[ -f /var/log/auth.log ]]; then
AUTH=/var/log/auth.log
elif [[ -f /var/log/secure ]]; then
AUTH=/var/log/secure
else
AUTH=""
fi

if [[ -n "$AUTH" ]]; then
echo "Log file: $AUTH"

```
grep -c "Failed password" "$AUTH" 2>/dev/null
grep -c "Accepted" "$AUTH" 2>/dev/null
```

else
warn "Authentication log not found"
fi

banner "SSH KEYS"

find / ( -name "id_rsa" -o -name "*.pem" -o -name "*.key" ) 
2>/dev/null | grep -v "^/proc"

banner "HISTORY FILES"

find /home /root -name ".bash_history" 2>/dev/null

banner "COMPLETE"

echo "Report saved to:"
echo "$OUTPUT"
