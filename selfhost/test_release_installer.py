"""selfhost/release_installer.py: the installer as it is served, for one tag.

What these hold: the copy it writes is the tag's own install.sh with its two
release lines filled in and nothing else changed, the commit is the one git
resolves the tag to, and a tag git does not know, a value of the wrong shape
or an install.sh whose release lines are not there once each and empty is
refused with nothing written.
"""
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import release_installer  # noqa: E402

COMMIT = "0123456789abcdef0123456789abcdef01234567"
SCRIPT = (HERE / "install.sh").read_text()


def git(*args, cwd):
    return subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=t@example.com",
                           "-c", "init.defaultBranch=main", *args], cwd=cwd, check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture()
def repository(tmp_path) -> Path:
    (tmp_path / "selfhost").mkdir()
    (tmp_path / "selfhost" / "install.sh").write_text(SCRIPT)
    git("init", "-q", cwd=tmp_path)
    git("add", ".", cwd=tmp_path)
    git("commit", "-q", "-m", "one", cwd=tmp_path)
    git("tag", "-a", "v1.2.3", "-m", "a release", cwd=tmp_path)
    return tmp_path


# ------------------------------------------------------------- refused

@pytest.mark.parametrize("tag", ["", "-v1", "v1 2", "v1;true", "v1$(id)", "v/1", "a" * 129])
def test_a_tag_of_the_wrong_shape_is_refused(tag):
    with pytest.raises(release_installer.ReleaseError):
        release_installer.stamp(SCRIPT, tag, COMMIT)


@pytest.mark.parametrize("commit", ["", COMMIT[:-1], COMMIT + "0", COMMIT.upper(),
                                    "g" * 40, COMMIT + "\n"])
def test_a_commit_of_the_wrong_shape_is_refused(commit):
    with pytest.raises(release_installer.ReleaseError):
        release_installer.stamp(SCRIPT, "v1.2.3", commit)


@pytest.mark.parametrize("text", [
    SCRIPT.replace("RELEASE_TAG=\n", ""),
    SCRIPT.replace("RELEASE_COMMIT=\n", ""),
    SCRIPT.replace("RELEASE_TAG=\n", "RELEASE_TAG=v0\n"),
    SCRIPT.replace("RELEASE_COMMIT=\n", f"RELEASE_COMMIT={COMMIT}\n"),
    SCRIPT.replace("RELEASE_TAG=\n", "RELEASE_TAG=\nRELEASE_TAG=\n"),
])
def test_an_installer_whose_release_lines_are_not_there_once_and_empty_is_refused(text):
    with pytest.raises(release_installer.ReleaseError):
        release_installer.stamp(text, "v1.2.3", COMMIT)


def test_a_tag_git_does_not_know_is_refused_and_nothing_is_written(repository, capsys):
    assert release_installer.main(["v9.9.9", "--repository", str(repository)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "v9.9.9" in captured.err


# ------------------------------------------------------------- written

def test_the_copy_is_the_installer_with_the_two_lines_filled_in():
    out = release_installer.stamp(SCRIPT, "v1.2.3", COMMIT)
    assert "\nRELEASE_TAG=v1.2.3\n" in out
    assert f"\nRELEASE_COMMIT={COMMIT}\n" in out
    assert out.replace("RELEASE_TAG=v1.2.3\n", "RELEASE_TAG=\n").replace(
        f"RELEASE_COMMIT={COMMIT}\n", "RELEASE_COMMIT=\n") == SCRIPT


def test_the_tags_own_installer_and_the_commit_git_resolves_it_to(repository, capsys):
    head = git("rev-parse", "HEAD", cwd=repository)
    # A later change to the working tree is not the tag's.
    (repository / "selfhost" / "install.sh").write_text(SCRIPT + "# later\n")
    assert release_installer.main(["v1.2.3", "--repository", str(repository)]) == 0
    out = capsys.readouterr().out
    assert f"\nRELEASE_COMMIT={head}\n" in out
    assert "\nRELEASE_TAG=v1.2.3\n" in out
    assert "# later" not in out


def test_the_filled_in_lines_are_read_by_a_shell_as_they_were_written(tmp_path):
    out = release_installer.stamp(SCRIPT, "v1.2.3", COMMIT)
    head = out[:out.index("main() {")]
    script = tmp_path / "head.sh"
    script.write_text(head + 'printf "%s %s" "$RELEASE_TAG" "$RELEASE_COMMIT"\n')
    done = subprocess.run(["sh", str(script)], capture_output=True, text=True, check=True)
    assert done.stdout == f"v1.2.3 {COMMIT}"
