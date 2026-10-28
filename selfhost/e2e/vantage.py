"""The test vantage's main process: make host keys, then become sshd.

The keys are made here, when the container starts, so no image ever holds
one. sshd logs to stderr, which is what `docker compose logs vantage` shows
and what the driver counts sessions in.
"""
import os
import subprocess

subprocess.run(["ssh-keygen", "-A"], check=True)
os.execv("/usr/sbin/sshd", ["/usr/sbin/sshd", "-D", "-e"])
