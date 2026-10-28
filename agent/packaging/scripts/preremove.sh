#!/bin/sh
# Pre-remove: stop and disable the timer, but ONLY on a real removal, never on
# an upgrade.
#
# An upgrade runs the OLD package's pre-remove during its cleanup phase, so
# tearing the timer down here stops the host reporting after an ordinary
# `apt upgrade` or `dnf upgrade`. That is exactly what happened across the whole
# fleet on 2026-08-15: every host that upgraded went silent until its timer was
# re-enabled by hand (docs/RECORD.md). Nothing caught it, because the scriptlet
# had no test and nobody runs a pre-remove by hand.
#
# The two packagers signal "this is an upgrade" differently, and nfpm passes
# each one's native argument straight through:
#
#   deb  passes "upgrade" as $1 when upgrading, "remove" on a real removal.
#   rpm  passes the number of versions that will remain afterwards: "1" on an
#        upgrade, "0" on the final erase.
#
# So the timer is left exactly as the operator set it for the upgrade cases,
# and torn down for everything else. Defaulting to "tear down" is the safe
# direction: the only cost of an unexpected argument is a disabled timer on a
# package that is going away anyway.
set -e

case "${1:-}" in
  upgrade|1)
    # An upgrade is in progress. The new package's units are already in place,
    # so leave the operator's timer choice untouched.
    exit 0
    ;;
esac

if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now whichports-agent.timer 2>/dev/null || true
fi
