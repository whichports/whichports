"""Open signup from the installer, end to end, on this machine.

    python3 selfhost/e2e/signup.py --out FOLDER            on ubuntu:26.04
    python3 selfhost/e2e/signup.py --out FOLDER --image debian:13

docs/SPEC-open-beta.md. selfhost/prove_install.py proves the installer on
each system against a stand-in for our API. This runs the same installer
against our API itself: the control plane's image serving its own signup
routes, with signup open, its mail going to a mail sink on this machine.
So the code that reaches the terminal is the one our API drew and mailed.

  1. Our side: the control plane's image, its ingest on 443 with a
     certificate made for the run, for the name `prober.invalid`, signup
     open, the landing's address set, and its mail relay a sink in a
     container beside it that keeps every message and sends none.
  2. The installer, as prove_install serves it, in a container of one
     system that trusts that certificate and finds our side by that name.
     It is answered on a terminal: the domain, the address, the password,
     yes, then a wrong code, then the code read from the sink.
  3. Read back: the line in `.env` names `prober.invalid` and its key works
     on our side; our side holds one signup instance with that address, no
     waiting code and no claim; one mail to the address carries the code
     and no link; the owner was told an instance signed up; the claim file
     is gone; and nothing of the address, the claim, the code or the line
     is in our side's journal.
  4. The line again: our probers are asked once whether they know the
     line, and nothing changes.
  5. The instance revoked by hand on our side, and the line again: the
     line is emptied, the installer signs up anew, no mail comes, since an
     address revoked by hand gets none, the code is skipped, and the stack
     runs without our probers.
  6. Everything removed: the stack and its volumes, and the three
     containers.

The terminal of each run, and the code mail as it was sent, are written to
--out, for the shots.
"""
import argparse
import email
import email.policy
import json
import re
import secrets
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import prove_install as p  # noqa: E402

OURS = "whichports-e2e-signup-ours"
SINK = "whichports-e2e-signup-mail"
OWNER = "owner@example.com"
SENDER = "whichports@example.com"
DATABASE = "/var/lib/whichports-controlplane/whichports.db"

# The mail relay our side is given: it takes every message, keeps it as a
# file and sends nothing on. Plain SMTP, which our side speaks to a relay
# that offers no STARTTLS and is given no credential (app/notify.py).
SINK_PROGRAM = r'''
import os, socketserver, time
os.makedirs("/tmp/mail", exist_ok=True)
class Relay(socketserver.StreamRequestHandler):
    def handle(self):
        def say(line):
            self.wfile.write((line + "\r\n").encode())
        say("220 sink")
        lines, data = [], False
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if data:
                if line == ".":
                    data = False
                    with open(f"/tmp/mail/{time.time_ns()}.eml", "w") as kept:
                        kept.write("\n".join(lines) + "\n")
                    lines = []
                    say("250 kept")
                else:
                    lines.append(line[1:] if line.startswith("..") else line)
                continue
            verb = line[:4].upper()
            if verb in ("EHLO", "HELO"):
                say("250 sink")
            elif verb == "DATA":
                data = True
                say("354 go on")
            elif verb == "QUIT":
                say("221 bye")
                return
            else:
                say("250 ok")
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("0.0.0.0", 2525), Relay).serve_forever()
'''

# Our side's ingest as its unit starts it, on 443 and with TLS, as root in
# its own container so it may take that port.
OURS_START = ('printf %s "$CERT" > /tmp/cert.pem && printf %s "$PRIVATE" > /tmp/key.pem'
              ' && exec /srv/controlplane/.venv/bin/uvicorn app.ingest:app --host 0.0.0.0'
              ' --port 443 --ssl-keyfile /tmp/key.pem --ssl-certfile /tmp/cert.pem'
              ' --no-proxy-headers --no-access-log')


def address_of(name: str) -> str:
    return p.run(["docker", "inspect", "-f",
                  "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                  name]).stdout.strip()


class Ours:
    """Our API, as the control plane serves it, for `prober.invalid`."""

    identity = ("/api/v1/prober/vantages", "unknown_key")

    def start(self, relay: str) -> None:
        p.run(["docker", "rm", "-f", OURS], check=False)
        self.certificate, private = p.certificate()
        p.run(["docker", "run", "-d", "--name", OURS, *p.OWN_LABEL, "--user", "root",
               "-e", "WHICHPORTS_INSTANCE_SIGNUP=open",
               "-e", "WHICHPORTS_BETA_LANDING=https://landing.invalid",
               "-e", f"WHICHPORTS_BASE_URL=https://{p.PROBERS}",
               "-e", f"WHICHPORTS_SMTP_HOST={relay}", "-e", "WHICHPORTS_SMTP_PORT=2525",
               "-e", f"WHICHPORTS_ALERT_TO={OWNER}", "-e", f"WHICHPORTS_ALERT_FROM={SENDER}",
               "-e", f"CERT={self.certificate}", "-e", f"PRIVATE={private}",
               "--entrypoint", "sh", p.IMAGE, "-c", OURS_START])
        self.address = address_of(OURS)
        time.sleep(3)

    def python(self, *argv) -> str:
        return p.run(["docker", "exec", "-u", "root", "-w", "/srv/controlplane", OURS,
                      p.PYTHON, *argv]).stdout

    def rows(self, query: str) -> list:
        program = ("import json, sqlite3, sys\n"
                   f"con = sqlite3.connect({DATABASE!r})\n"
                   "print(json.dumps(con.execute(sys.argv[1]).fetchall()))\n")
        return json.loads(self.python("-c", program, query))

    def journal(self) -> str:
        done = p.run(["docker", "logs", OURS], check=False)
        return done.stdout + done.stderr


def mails() -> list:
    """Every message the sink kept, oldest first."""
    program = ("import glob, json\n"
               "print(json.dumps([open(n).read() for n in sorted(glob.glob('/tmp/mail/*.eml'))]))\n")
    found = p.run(["docker", "exec", SINK, p.PYTHON, "-c", program]).stdout
    return [email.message_from_string(text, policy=email.policy.default)
            for text in json.loads(found or "[]")]


def to(address: str) -> list:
    return [m for m in mails() if address in str(m["To"])]


def text_of(message) -> str:
    return message.get_body(preferencelist=("plain",)).get_content()


def html_of(message) -> str:
    part = message.get_body(preferencelist=("html",))
    return part.get_content() if part else ""


def the_code(wait=60):
    """A function for the code's question: the eight digits of the newest
    mail to the address, waited for, or nothing, which skips."""
    def read() -> str:
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            found = to(p.EMAIL)
            if found:
                digits = re.findall(r"\b[0-9]{8}\b", text_of(found[-1]))
                return digits[0] if digits else ""
            time.sleep(1)
        return ""
    return read


def env_line(box) -> str:
    return box.sh(f"grep '^WHICHPORTS_PROBER_INVITE=' {p.SELFHOST}/.env").stdout.strip()


def keep(out: Path, name: str, text: str) -> None:
    (out / name).write_text(text)
    print(f"  kept {out / name}")


def prove(image: str, out: Path) -> None:
    sink, ours, box = None, Ours(), p.Box(image)
    password = "Prove-" + secrets.token_hex(6) + "-1"
    try:
        p.run(["docker", "rm", "-f", SINK], check=False)
        p.run(["docker", "run", "-d", "--name", SINK, *p.OWN_LABEL, "--entrypoint", p.PYTHON,
               p.IMAGE, "-c", SINK_PROGRAM])
        sink = address_of(SINK)
        ours.start(sink)
        box.start()
        print(f"  {box.versions()}")
        box.trust(ours)
        box.put_the_release()

        print("  the line: a wrong code, then the code from the mail")
        code, shown = p.on_a_terminal(p.the_line(box), [
            p.DOMAIN, p.EMAIL, password, password, "yes", "00000000", the_code()])
        keep(out, "terminal-first-run.txt", shown)
        p.show_tail(shown)
        p.say(code == 0 and "whichports is running." in shown, f"the line ended 0, exit {code}")
        p.say(shown.count("That code did not work.") == 1, "a wrong code was said once")
        p.say(password not in shown, "the terminal never showed the password")

        line = env_line(box).removeprefix("WHICHPORTS_PROBER_INVITE=")
        p.say(re.fullmatch(rf"whpinvite1_{re.escape(p.PROBERS)}_whpi_[0-9a-f]{{64}}_whpp_[0-9a-f]{{64}}",
                           line) is not None, "the line in .env names our side, with two keys")
        api_key = line.split("_whpi_")[1].split("_whpp_")[0] if "_whpi_" in line else ""
        status = box.sh("printf 'Authorization: Bearer whpi_%s\\n' " + api_key
                        + f" | curl -sS -o /dev/null -w '%{{http_code}}' -H @- https://{p.PROBERS}/api/v1/prober/vantages",
                        check=False).stdout
        p.say(status == "200", f"its API key works on our side: {status}")
        instances = ours.rows("SELECT origin, contact_email, revoked_at FROM probe_instances")
        p.say(instances == [["signup", p.EMAIL, None]], f"our side holds one signup instance: {instances}")
        left = ours.rows("SELECT (SELECT COUNT(*) FROM instance_signups),"
                         " (SELECT COUNT(*) FROM instance_signup_claims)")
        p.say(left == [[0, 0]], f"no waiting code and no claim are left on our side: {left}")
        claim_file = box.sh(f"test -e {p.SELFHOST}/.prober-claim && echo kept || echo gone").stdout.strip()
        p.say(claim_file == "gone", f"the claim file is {claim_file}")

        sent = to(p.EMAIL)
        p.say(len(sent) == 1, f"{len(sent)} mail to the address")
        if sent:
            mail = sent[0]
            body = text_of(mail)
            the_digits = re.findall(r"\b[0-9]{8}\b", body)
            p.say(str(mail["Subject"]) == "[whichports] Your code" and len(the_digits) == 1
                  and body.strip().count("\n") == 0, f"the mail is one line with the code: {body.strip()!r}")
            html = html_of(mail)
            p.say("http" not in body and "href" not in html and "<a " not in html
                  and the_digits[0] in html, "the mail holds no link and no button")
            keep(out, "mail-code.html", html)
        owner = [str(m["Subject"]) for m in to(OWNER)]
        p.say(owner == ["[whichports] An instance signed up"], f"the owner was told: {owner}")
        journal = ours.journal()
        secrets_seen = [w for w in (p.EMAIL, line, api_key) if w and w in journal]
        if sent:
            secrets_seen += [d for d in re.findall(r"\b[0-9]{8}\b", text_of(sent[0])) if d in journal]
        p.say(not secrets_seen and "instance signup: collect made" in journal,
              f"our side's journal says what happened and holds no address, code or key {secrets_seen}")

        print("  the same line again")
        before = box.sh(f"stat -c '%Y %s' {p.SELFHOST}/.env").stdout
        code, shown = p.on_a_terminal(p.the_line(box), [p.DOMAIN, p.EMAIL, password, password, "yes"])
        after = box.sh(f"stat -c '%Y %s' {p.SELFHOST}/.env").stdout
        p.say(code == 0 and "our probers know the line in" in shown and before == after
              and "Type the 8-digit code" not in shown, f"exit {code}, the line kept, nothing asked")

        print("  revoked by hand on our side, and the line again")
        name = ours.rows("SELECT name FROM probe_instances")[0][0]
        ours.python("-m", "app.instances_cli", "revoke", "--name", name)
        count = len(mails())
        code, shown = p.on_a_terminal(p.the_line(box), [
            p.DOMAIN, p.EMAIL, password, password, "yes", the_code(wait=10)])
        keep(out, "terminal-revoked-run.txt", shown)
        p.show_tail(shown)
        p.say(code == 0 and "no longer know the line in" in shown
              and "The install goes on without our probers." in shown
              and "* starting the stack again without it" in shown,
              f"exit {code}: the line emptied, a signup, the code skipped, the stack without it")
        p.say(env_line(box) == "WHICHPORTS_PROBER_INVITE=", f".env: {env_line(box)}")
        p.say(len(mails()) == count, "no mail went: an address revoked by hand gets none")
        claims = ours.rows("SELECT COUNT(*) FROM instance_signup_claims")
        p.say(claims == [[1]], f"our side kept the claim all the same: {claims}")
    except Exception as exc:  # noqa: BLE001, a run that broke is reported, then removed
        p.say(False, f"the run stopped: {exc}")
    finally:
        box.remove()
        p.run(["docker", "rm", "-f", OURS, SINK], check=False)
        gone = p.run(["docker", "ps", "-a", "-q", "--filter", "name=whichports-e2e-signup",
                      "--filter", f"name={box.name}"]).stdout.strip()
        p.say(not gone, "the containers are gone")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--image", default="ubuntu:26.04", choices=sorted(p.SYSTEMS))
    parser.add_argument("--out", required=True, type=Path,
                        help="a new folder for the terminals and the mail")
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=False)
    if p.run(["docker", "info"], check=False, timeout=60).returncode != 0:
        print("signup: Docker is not running, so nothing was tested")
        return 1
    # Our side runs from the control plane's image as the last install of
    # this tree built it, so an image from before the collect route is no
    # proof of anything.
    route = p.run(["docker", "run", "--rm", *p.OWN_LABEL, "--entrypoint", p.PYTHON, p.IMAGE,
                   "-c", "from app import instancesignup_routes as r; print(r.COLLECT_PATH)"],
                  check=False).stdout.strip()
    if route != "/api/v1/instance-signup/collect":
        print(f"signup: {p.IMAGE} has no collect route. Build it from this tree first,"
              " with selfhost/prove_install.py ubuntu:26.04. Nothing was tested.")
        return 1
    print(f"== {args.image}")
    prove(args.image, args.out)
    print()
    if p.failures:
        print(f"SIGNUP FAILED, {len(p.failures)} checks:")
        for what in p.failures:
            print(f"  {what}")
        return 1
    print("SIGNUP PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
