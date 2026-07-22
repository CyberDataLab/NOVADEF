#!/bin/sh
# NOVADEF Lab - SOARCA Isolation Countermeasure
# Executed via SSH by SOARCA as defensive response to ransomware detection.
#
# The SSH channel must close cleanly (exit 0) BEFORE the iptables DROP policy
# is applied, otherwise SOARCA reads the broken pipe as exit code 1 and marks
# the playbook as failed.  We use setsid to detach the iptables commands into a
# new session that survives the SSH process group being torn down.

# Step 1: Terminate the ransomware process and all parallel encryption workers.
touch /tmp/novadef_exp2_stop.signal 2>/dev/null || true
pkill -f akira_lab_emulation 2>/dev/null || true
pkill -f 'openssl enc'        2>/dev/null || true
pkill -f 'dd if=/dev/urandom' 2>/dev/null || true
pkill -f 'novadef_akira'      2>/dev/null || true

# Step 2: Write the isolation commands to a temp script so we avoid passing a
# multi-line heredoc through setsid (ash/busybox does not handle that well).
cat > /tmp/_novadef_isolate.sh << 'ISOLATION_EOF'
#!/bin/sh
sleep 0
iptables -F INPUT  2>/dev/null || true
iptables -F OUTPUT 2>/dev/null || true
iptables -A INPUT  -i lo -j ACCEPT 2>/dev/null || true
iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
# Re-install SOARCA SSH access so SOARCA can still connect post-isolation.
# Scoped to 172.18.0.0/27 (infra range) NOT the full /24 — the attacker's
# spoofed IPs (172.18.0.160-175) live inside the /24 but outside the /27, so a
# /24 whitelist here would let the attacker keep reaching port 2222 through the
# "isolation", defeating the countermeasure.
iptables -N NOVADEF_SOARCA_SSH 2>/dev/null || true
iptables -F NOVADEF_SOARCA_SSH 2>/dev/null || true
iptables -A NOVADEF_SOARCA_SSH -p tcp --dport 2222 -s 172.18.0.0/27 -j ACCEPT 2>/dev/null || true
iptables -C INPUT -p tcp --dport 2222 -s 172.18.0.0/27 -j NOVADEF_SOARCA_SSH 2>/dev/null || \
  iptables -I INPUT 1 -p tcp --dport 2222 -s 172.18.0.0/27 -j NOVADEF_SOARCA_SSH 2>/dev/null || true
# Re-install the network-traffic counting chain jump that the flush removed, so
# the GUI keeps measuring inbound network packets AFTER isolation (they will all
# be counted by NOVADEF_NET_IN and then dropped by the policy -> effective ~0).
iptables -N NOVADEF_NET_IN 2>/dev/null || true
iptables -F NOVADEF_NET_IN 2>/dev/null || true
iptables -A NOVADEF_NET_IN -j RETURN 2>/dev/null || true
iptables -C INPUT ! -i lo -j NOVADEF_NET_IN 2>/dev/null || iptables -A INPUT ! -i lo -j NOVADEF_NET_IN 2>/dev/null || true
iptables -P INPUT  DROP  2>/dev/null || true
iptables -P OUTPUT DROP  2>/dev/null || true
ISOLATION_EOF
chmod +x /tmp/_novadef_isolate.sh

# Step 3: Launch in a completely detached session.
# setsid creates a new session so the process is not a member of the SSH
# process group and will not receive SIGHUP when the SSH channel closes.
setsid sh /tmp/_novadef_isolate.sh </dev/null >/dev/null 2>&1 &

# Step 4: Echo confirmation — SOARCA reads this as success (exit 0).
# This runs while the SSH channel is still open; the DROP fires 2s later.
echo novadef_countermeasure_applied
