"""The installer as get.whichports.com serves it, for one release.

    python3 selfhost/release_installer.py v0.2.0 > selfhost.sh

In the repository selfhost/install.sh names no release: its RELEASE_TAG and
RELEASE_COMMIT lines are empty, and a copy with them empty installs nothing.
This writes the tag's own install.sh, read from git at that tag, with the two
lines filled in: the tag, and the commit git resolves it to in this
repository. The copy that is served then clones that tag and refuses to build
any other commit, so a tag moved on the server where the repository lives
cannot change what root builds.

It refuses a tag git does not know, a tag or commit of a shape a shell would
read as more than a word, and an install.sh whose two lines are not there once
each and empty. It writes to standard output and changes nothing: putting the
copy on get.whichports.com is a publish, and a publish is the owner's.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT_PATH = "selfhost/install.sh"

# Letters, digits, dots, hyphens and underscores, starting with a letter or a
# digit: nothing a shell or git reads as anything but a name.
TAG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
LINES = ("RELEASE_TAG=", "RELEASE_COMMIT=")


class ReleaseError(ValueError):
    """The copy cannot be written for this tag."""


def stamp(text: str, tag: str, commit: str) -> str:
    """install.sh with its two release lines filled in, and nothing else
    changed."""
    if not isinstance(tag, str) or not TAG_RE.fullmatch(tag):
        raise ReleaseError(f"{tag!r} is not a tag name of letters, digits, dots,"
                           " hyphens and underscores")
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise ReleaseError(f"{commit!r} is not a commit of 40 lowercase hex characters")
    lines = text.split("\n")
    for line in LINES:
        if lines.count(line) != 1:
            raise ReleaseError(f"{SCRIPT_PATH} has no single empty {line} line")
    return "\n".join(f"RELEASE_TAG={tag}" if line == "RELEASE_TAG=" else
                     f"RELEASE_COMMIT={commit}" if line == "RELEASE_COMMIT=" else line
                     for line in lines)


def git(repository: Path, *args) -> str:
    done = subprocess.run(["git", "-C", str(repository), *args],
                          capture_output=True, text=True)
    if done.returncode != 0:
        raise ReleaseError(done.stderr.strip() or f"git {args[0]} failed")
    return done.stdout


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("tag")
    parser.add_argument("--repository", type=Path, default=REPO,
                        help="the repository the tag is in, this one by default")
    args = parser.parse_args(argv)
    try:
        if not TAG_RE.fullmatch(args.tag):
            raise ReleaseError(f"{args.tag!r} is not a tag name")
        commit = git(args.repository, "rev-parse", "--verify", "--quiet",
                     f"refs/tags/{args.tag}^{{commit}}").strip()
        text = git(args.repository, "show", f"{commit}:{SCRIPT_PATH}")
        out = stamp(text, args.tag, commit)
    except ReleaseError as exc:
        print(f"release_installer: {args.tag}: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
