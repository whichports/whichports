#!/usr/bin/env python3
"""Time a dashboard render against a generated database.

    python3 bench_render_live.py --hosts 4 --days 7 --runs 3

It builds a database of its own under a temporary directory, one host document
every fifteen minutes per host, then times `render()` and `load()` over it. The
generated documents are synthetic: the shape is the agent's
(`agent/internal/hostdoc/hostdoc.go`) and the sizes are chosen to sit near a
real one, but nothing here is a measurement of a real host.

Two timings are printed and they are different questions:

  cold  the first render over this database, so nothing computed by an earlier
        render is there to be reused. It is what the first browser after a
        deploy gets.
  warm  every render after that.

`--keep` prints the database path and leaves it behind, which is what to use
when profiling with cProfile rather than timing.
"""
import argparse
import json
import pathlib
import random
import shutil
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402

SCHEMA = """
CREATE TABLE workspaces (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, token_hash TEXT UNIQUE,
    kind TEXT NOT NULL DEFAULT 'agent',
    created_at TEXT NOT NULL, revoked_at TEXT, last_report_at TEXT,
    paused INTEGER NOT NULL DEFAULT 0, auto_named INTEGER NOT NULL DEFAULT 0,
    workspace_id INTEGER NOT NULL DEFAULT 1);
CREATE TABLE reports (
    id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
    received_at TEXT NOT NULL, collected_at_unix INTEGER NOT NULL,
    schema_version INTEGER NOT NULL, document TEXT NOT NULL);
CREATE TABLE report_digests (
    report_id INTEGER PRIMARY KEY REFERENCES reports(id),
    version TEXT NOT NULL, digest TEXT NOT NULL);
CREATE INDEX idx_reports_host_received ON reports(host_id, received_at DESC);
INSERT INTO workspaces (id, name, created_at) VALUES (1, 'default', '2026-08-01T00:00:00+00:00');
"""

PROCESSES = ["sshd", "caddy", "postgres", "redis-server", "chronyd", "systemd-resolve",
             "node", "python3", "dockerd", "containerd", "nginx", "postfix"]


def listeners(rng, count):
    out = []
    for i in range(count):
        out.append({
            "protocol": "tcp" if i % 4 else "udp",
            "family": "v4" if i % 3 else "v6",
            "bind_address": ["0.0.0.0", "127.0.0.1", "::", "10.0.0.5"][i % 4],
            "port": 1024 + i * 7,
            "process_name": PROCESSES[i % len(PROCESSES)],
            "pid": 100 + i,
            "uid": 0,
            "inode": 3000 + i,
        })
    return out


def nft_table(rng, family, name, chains, rules):
    return {
        "family": family, "name": name,
        "chains": [{
            "name": f"chain{c}", "type": "filter", "hook": "input",
            "priority": 0, "policy": "drop",
            "rules": [{
                "handle": r,
                "text": (f"ip saddr 10.{c}.{r % 250}.0/24 ip daddr 192.0.2.{r % 250}"
                         f" tcp dport {1000 + r} ct state new,established"
                         f" counter packets {r * 17} bytes {r * 1301}"
                         f' comment "rule {r} in chain {c}, written by the'
                         f' zone file" accept'),
                "rendered": "full",
            } for r in range(rules)],
        } for c in range(chains)],
    }


def document(rng, hostname, when, extra_listener):
    """One host document of roughly the size a real one has."""
    listening = listeners(rng, 24)
    if extra_listener:
        listening.append({"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
                          "port": 9999, "process_name": "deploy-helper", "pid": 4242})
    return {
        "schema_version": 1,
        "hostname": hostname,
        "agent_version": "0.1.6",
        "collected_at_unix": int(when.timestamp()),
        "sockets": {"status": "collected", "listening": listening},
        "interface_addresses": {"status": "collected", "interfaces": [
            {"name": n, "addresses": [{"address": a, "family": f, "scope": "global"}]}
            for n, a, f in (("lo", "127.0.0.1", "v4"), ("eth0", "192.0.2.10", "v4"),
                            ("eth0", "2001:db8::10", "v6"))]},
        "nftables": {"status": "collected", "tables": [
            nft_table(rng, "inet", "firewalld", 4, 30),
            nft_table(rng, "ip", "filter", 2, 20),
        ]},
        "iptables": {"status": "not_present"},
        "ip6tables": {"status": "not_present"},
        "ufw": {"status": "collected", "conf": {"ENABLED": "yes", "IPV6": "yes"},
                "rules": [{"text": f"-A ufw-user-input -p tcp --dport {1000 + i} -j ACCEPT"}
                          for i in range(20)]},
        "firewalld": {"status": "collected", "conf": {"DefaultZone": "public"}},
        "containers": {"status": "collected", "docker": [
            {"id": f"c{i}", "name": f"svc{i}", "image": "example/app:1",
             "ports": [{"host_ip": "0.0.0.0", "host_port": 8000 + i,
                        "container_port": 8000, "protocol": "tcp"}]}
            for i in range(6)], "podman": []},
        "rule_files": {"status": "collected", "files": [
            {"path": f"/etc/firewalld/zones/zone{i}.xml", "mtime_unix": 1750000000 + i,
             "size": 400 + i, "sha256": f"{i:064x}"} for i in range(24)]},
        "overlays": {"status": "collected", "interfaces": []},
        "socket_units": {"status": "collected", "units": [
            {"unit": f"unit{i}.socket", "listen": [f"0.0.0.0:{7000 + i}"],
             "service": f"unit{i}.service"} for i in range(8)]},
    }


def build(path, hosts, days, per_hour, now):
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    rng = random.Random(7)
    step = timedelta(hours=1) / per_hour
    count = int(days * 24 * per_hour)
    sizes = []
    for h in range(hosts):
        name = f"box{h + 1}"
        cur = con.execute(
            "INSERT INTO hosts (name, token_hash, created_at, last_report_at,"
            " workspace_id) VALUES (?, ?, ?, ?, 1)",
            (name, f"hash-{name}", (now - timedelta(days=days)).isoformat(),
             now.isoformat()))
        host_id = cur.lastrowid
        rows = []
        for i in range(count):
            when = now - step * i
            doc = document(rng, name, when, extra_listener=(i // 48) % 2 == 0)
            text = json.dumps(doc)
            sizes.append(len(text))
            rows.append((host_id, when.isoformat(), int(when.timestamp()), 1, text))
        con.executemany(
            "INSERT INTO reports (host_id, received_at, collected_at_unix,"
            " schema_version, document) VALUES (?, ?, ?, ?, ?)", rows)
    con.commit()
    con.close()
    return len(sizes), sum(sizes) // max(1, len(sizes))


def timed(fn):
    start = time.perf_counter()
    fn()
    return time.perf_counter() - start


def median(values):
    return sorted(values)[len(values) // 2]


def without_the_table(path):
    """The database as it is before `db.init` has created the digest table,
    which is also what every render did before the table existed."""
    con = sqlite3.connect(path)
    con.execute("DROP TABLE IF EXISTS report_digests")
    con.commit()
    con.close()


def with_an_empty_table(path):
    """The table there and holding nothing, which is a first render after a
    deploy that changed the digest."""
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE IF NOT EXISTS report_digests (report_id INTEGER"
                " PRIMARY KEY REFERENCES reports(id), version TEXT NOT NULL,"
                " digest TEXT NOT NULL)")
    con.execute("DELETE FROM report_digests")
    con.commit()
    con.close()


def stored_digest_bytes(path):
    con = sqlite3.connect(path)
    try:
        return con.execute("SELECT count(*), coalesce(sum(length(digest)), 0)"
                           " FROM report_digests").fetchone()
    except sqlite3.OperationalError:
        return (0, 0)
    finally:
        con.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    ap.add_argument("--hosts", type=int, default=4)
    ap.add_argument("--days", type=float, default=7)
    ap.add_argument("--per-hour", type=int, default=4)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    now = datetime(2026, 8, 27, 12, 0, 0, tzinfo=timezone.utc)
    workdir = pathlib.Path(tempfile.mkdtemp(prefix="whichports-bench-"))
    path = str(workdir / "bench.db")
    made = time.perf_counter()
    docs, average = build(path, args.hosts, args.days, args.per_hour, now)
    print(f"{args.hosts} hosts, {docs} documents, {average / 1024:.1f} kB each, "
          f"{pathlib.Path(path).stat().st_size / 1e6:.0f} MB database, "
          f"built in {time.perf_counter() - made:.1f}s")

    def render():
        rl.render(path, now=now, workspace_id=1)

    def load():
        rl.load(path, now=now, workspace_id=1)

    # One render before anything is timed. The first one in a process pays for
    # importing the template and the join engine, which is not what any of
    # this is measuring.
    without_the_table(path)
    render()

    for name, prepare, runs in (
            ("no digest table", without_the_table, args.runs),
            ("cold, empty table", with_an_empty_table, args.runs),
            ("warm", lambda _path: None, args.runs)):
        for what, call in (("render", render), ("load", load)):
            times = []
            for _ in range(runs):
                prepare(path)
                times.append(timed(call))
            spread = " ".join(f"{t:.3f}" for t in times)
            print(f"{name:>18}  {what:<7} median {median(times):.3f}s   ({spread})")

    rows, size = stored_digest_bytes(path)
    print(f"{rows} digests stored, {size / 1e6:.1f} MB, "
          f"database now {pathlib.Path(path).stat().st_size / 1e6:.0f} MB")

    if args.keep:
        print(f"database kept at {path}")
    else:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
