#!/usr/bin/env bash
# recon.sh - READ ONLY. Collects every firewall layer on one host.
# Changes nothing. Run with sudo so socket->process mapping works.
#
#   sudo bash recon.sh > recon-$(hostname).txt 2>&1
#
# The question it answers: for every port bound to a public address,
# which layers would allow or block it, and do they agree?

set -uo pipefail
h() { printf '\n\n===== %s =====\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

echo "host: $(hostname -f 2>/dev/null || hostname)   date: $(date -Is)"
echo "os:   $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"
echo "kernel: $(uname -r)"

# ---------------------------------------------------------------- LAYER 0
# What is actually listening, and on which address. 0.0.0.0 or :: means
# "reachable if anything upstream lets it through". 127.0.0.1 means it is
# unreachable no matter what the firewalls say.
h "LAYER 0: listening sockets"
if have ss; then
  ss -tulpnH 2>/dev/null | awk '{printf "%-5s %-24s %s\n", $1, $5, $7}' | sort -u
else
  netstat -tulpn 2>/dev/null
fi

h "LAYER 0b: PUBLICLY BOUND ONLY (this is the list that matters)"
ss -tulpnH 2>/dev/null \
  | awk '$5 ~ /^(0\.0\.0\.0|\*|\[::\]|::):/ {printf "%-5s %-24s %s\n", $1, $5, $7}' \
  | sort -u

# ---------------------------------------------------------------- BACKEND
# On modern Debian/Ubuntu, "iptables" is really iptables-nft. Knowing which
# backend is live decides where the real ruleset lives.
h "WHICH FIREWALL BACKEND IS LIVE"
have iptables && iptables -V
have nft && echo "nft tables present:" && nft list tables 2>/dev/null
for s in ufw firewalld nftables netfilter-persistent docker tailscaled; do
  printf '%-22s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || echo n/a)"
done

# ---------------------------------------------------------------- LAYER 1
h "LAYER 1: ufw"
have ufw && { ufw status verbose; echo; ufw status numbered; } || echo "ufw not installed"

h "LAYER 1b: firewalld"
have firewall-cmd && { firewall-cmd --list-all-zones 2>/dev/null; } || echo "firewalld not installed"

# ---------------------------------------------------------------- LAYER 2
# The merged truth. If nft is the backend this contains ufw's rules,
# Docker's rules and Tailscale's rules all together.
h "LAYER 2: nftables full ruleset (the merged reality)"
have nft && nft list ruleset 2>/dev/null || echo "nft unavailable"

h "LAYER 2b: iptables v4 (filter + nat)"
have iptables-save && iptables-save 2>/dev/null || echo "iptables-save unavailable"

h "LAYER 2c: ip6tables v6 - CHECK THIS, Hetzner cloud FW is IPv4 ONLY"
have ip6tables-save && ip6tables-save 2>/dev/null || echo "ip6tables-save unavailable"

# ---------------------------------------------------------------- LAYER 3
# Docker writes DNAT into nat/PREROUTING and it is evaluated BEFORE ufw.
h "LAYER 3: Docker published ports"
if have docker; then
  docker ps --format '{{.Names}}\t{{.Ports}}' 2>/dev/null
  echo; echo "--- nat DOCKER chain ---"
  iptables -t nat -L DOCKER -n --line-numbers 2>/dev/null
  echo; echo "--- DOCKER-USER chain ---"
  iptables -L DOCKER-USER -n -v --line-numbers 2>/dev/null
  echo; echo "--- compose files that publish to a public address ---"
  grep -rEl '^\s*-\s*"?[0-9]+:[0-9]+' /opt /srv /root /home \
       --include='docker-compose*.y*ml' --include='compose*.y*ml' 2>/dev/null | head -40
else
  echo "docker not installed"
fi

# ---------------------------------------------------------------- LAYER 4
# Tailscale's chains are invisible to some iptables views. Open upstream bug.
h "LAYER 4: Tailscale chains"
if have tailscale; then
  tailscale status --peers=false 2>/dev/null | head -5
  iptables -S 2>/dev/null | grep -E 'ts-(input|forward)' || echo "no ts- chains in iptables view"
  nft list ruleset 2>/dev/null | grep -A8 -E 'ts-(input|forward)' || echo "no ts- chains in nft view"
else
  echo "tailscale not installed"
fi

# ---------------------------------------------------------------- ADDRESSES
h "PUBLIC ADDRESSES (probe targets - note v4 AND v6 separately)"
ip -4 addr show scope global | awk '/inet /{print "v4: "$2}'
ip -6 addr show scope global | awk '/inet6 /{print "v6: "$2}'

# ---------------------------------------------------------------- RECENCY
# "Opened it for testing and forgot" is the failure mode. When did rules change?
h "WHEN WERE FIREWALL RULES LAST TOUCHED"
for f in /etc/ufw/user.rules /etc/ufw/user6.rules /etc/nftables.conf \
         /etc/iptables/rules.v4 /etc/iptables/rules.v6 \
         /etc/firewalld/zones/public.xml; do
  [ -f "$f" ] && printf '%-34s %s\n' "$f" "$(stat -c '%y' "$f" 2>/dev/null)"
done
echo "--- recent ufw / firewall commands in shell history ---"
grep -hE '(ufw|iptables|nft|firewall-cmd) ' /root/.bash_history /home/*/.bash_history 2>/dev/null \
  | tail -30 || echo "no history available"

echo; echo "===== END $(hostname) ====="
