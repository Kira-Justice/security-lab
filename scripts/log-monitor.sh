#!/bin/bash

LOG=/var/log/auth.log
THRESHOLD=50

echo "=== AUTH SUMMARY $(date) ==="
echo "Failed attempts : $(grep -c 'Failed password' $LOG 2>/dev/null)"
echo "Successful logins: $(grep -c 'Accepted' $LOG 2>/dev/null)"

echo ""
echo "=== TOP BRUTE-FORCE IPs ==="
grep "Failed password" $LOG 2>/dev/null \
  | awk '{print $11}' | sort | uniq -c | sort -rn | head -10

echo ""
echo "=== ALERT: IPs EXCEEDING $THRESHOLD FAILURES ==="
grep "Failed password" $LOG 2>/dev/null \
  | awk '{print $11}' | sort | uniq -c | sort -rn \
  | awk -v t=$THRESHOLD '$1>t {print "[!] "$2, "| attempts:", $1}'

echo ""
echo "=== SUCCESSFUL LOGINS (last 10) ==="
grep "Accepted" $LOG 2>/dev/null \
  | awk '{print $1,$2,$3,"from:"$11}' | tail -10

echo ""
echo "=== RECENT SUDO COMMANDS ==="
grep "COMMAND=" $LOG 2>/dev/null | tail -10

echo ""
echo "=== RECENT PACKAGE INSTALLS ==="
grep " install " /var/log/dpkg.log 2>/dev/null | tail -10
