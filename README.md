# whichports

For every port on every server you own: is something listening, is it
reachable from the internet, and which layer decided that.

Your firewall rules do not tell you which ports are reachable. whichports
measures it from both sides and compares:

- **From inside.** An agent on each server reads the listening sockets and
  every filtering layer: nftables, iptables, ufw, firewalld, and what Docker
  and Podman publish. It reads and never writes, it opens no listening socket,
  and it accepts no command.
- **From outside.** Probers connect to each port, IPv4 and IPv6 answered
  separately. A TCP connect, and on a TLS port a handshake to read the
  certificate. Nothing beyond the handshake.

Where the two disagree, the dashboard names the layer and quotes the rule.

## What is here

| Path | What |
|---|---|
| `selfhost/` | Run it yourself with Docker Compose. **Start with `selfhost/README.md`** |
| `agent/` | The agent, in Go, one static binary. `agent/README.md` says what it reads and with which privileges |
| `controlplane/` | The service agents report to, the storage, the alerts and the prober API, in Python |
| `site/app/`, `site/theme.py` | The dashboard, rendered by the control plane |
| `ops/cve/` | The CVE check's daily build, a systemd service and its timer, which the self-hosted worker runs on the timer's schedule |

## The beta

whichports is in a private beta, by invitation. You run the control plane and
the dashboard on a server of your own, so what your agents read stays with
you. The view from outside comes from our probers, which your instance asks
through an API, with keys that come with an invitation. `selfhost/README.md`
says what our side learns when it does.

To ask for an invitation, or about anything here: hello@whichports.com.

## Licence

Apache-2.0, in `LICENSE`. The fonts in `site/fonts/` are under the SIL Open
Font License, in `site/fonts/OFL.txt`, and `site/THIRD_PARTY_NOTICES.md` lists
what else is included and under which terms.
