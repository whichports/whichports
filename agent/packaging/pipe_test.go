package packaging

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/whichports/whichports/agent/internal/report"
)

// The installer arrives through a pipe, `curl ... | sudo sh -s -- enroll ...`,
// and these tests run it that way: the script on standard input, the
// arguments after `-s --`, and every program it calls replaced by a stub that
// writes its name to a log. Nothing is fetched, installed or written. The
// stub `id -u` answers 1, so a complete script stops at its own root check,
// which is after the argument check and before anything touches the machine,
// and a non-empty log means main ran.
//
// What they hold in place is the answer to docs/RECORD.md 4.228: the Add
// server window's command chained the enrolment after the pipe with &&, a
// pipe's exit status is the shell's, and a shell given nothing exits 0, so a
// failed download carried on to "sudo: whichports-agent: command not found".

// pipeShells are the shells the script is fed to. sh is whatever this machine
// has, and dash and bash are the two a server's /bin/sh is: dash on the
// Debian family, bash on the RHEL family.
func pipeShells(t *testing.T) [][]string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the installer is a POSIX shell script")
	}
	shells := [][]string{{"sh"}}
	if _, err := exec.LookPath("dash"); err == nil {
		shells = append(shells, []string{"dash"})
	}
	if _, err := exec.LookPath("bash"); err == nil {
		shells = append(shells, []string{"bash", "--posix"})
	}
	return shells
}

// pipeStubs writes one logging stub per program the installer calls and
// returns the directory and the log.
func pipeStubs(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "ran.log")
	for _, name := range []string{"id", "gpg", "curl", "apt-get", "dnf",
		"dpkg-query", "mktemp", "setfacl", "systemctl", "awk", "cat", "chmod",
		"cp", "mkdir", "rm", "grep", "readlink", "dirname"} {
		stub := "#!/bin/sh\nprintf '%s %s\\n' " + name + " \"$*\" >> " + shellQuote(log) + "\n"
		if name == "id" {
			// Not root, so the script stops right after proving main ran.
			stub += "echo 1\n"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(stub), 0o755); err != nil {
			t.Fatalf("writing the %s stub: %v", name, err)
		}
	}
	return dir, log
}

// pipeInto feeds script to shell on standard input with args after `-s --`.
// It returns what ran, the combined output and the exit error.
func pipeInto(t *testing.T, shell []string, stubs, log string, script []byte, args ...string) (string, string, error) {
	t.Helper()
	os.Remove(log)
	path, err := exec.LookPath(shell[0])
	if err != nil {
		t.Fatalf("finding %s: %v", shell[0], err)
	}
	argv := append(append([]string{}, shell[1:]...), "-s", "--")
	cmd := exec.Command(path, append(argv, args...)...)
	cmd.Stdin = bytes.NewReader(script)
	// Only the stubs are on PATH, so nothing the script calls is real.
	cmd.Env = []string{"PATH=" + stubs, "HOME=" + stubs}
	out, runErr := cmd.CombinedOutput()
	ran, readErr := os.ReadFile(log)
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatalf("reading the log: %v", readErr)
	}
	return string(ran), string(out), runErr
}

var enrollArgs = []string{"enroll", "--server=https://app.example.invalid",
	"--credential=whp_cleanbox0123456789abcdefghijklmnop"}

// A download that stops halfway must run nothing. The script's body is one
// function, called on the last line inside braces, and a shell runs neither
// until it has read the whole of it.
//
// The full measurement, 2026-10-02: every prefix of the script, byte by
// byte, fed to dash, bash --posix and zsh. No cut-off script ran anything in
// any of the three. The installer before this change ran something on 8,079
// of its 10,564 prefixes. And with a bare `main "$@"` as the last line, two
// cuts, after "main" and after "main ", ran the install with no arguments,
// which is what the braces are for.
//
// That run takes half a minute a shell, so this one samples: every 53rd
// byte, and every byte of the last 200, which covers the end of main and
// the whole last line.
func TestACutOffInstallerRunsNothing(t *testing.T) {
	script := []byte(installerSource(t))
	// The script without its final newline is the whole script, so the cuts
	// stop one byte short of that.
	complete := len(script) - 1
	if script[complete] != '\n' {
		t.Fatal("install.sh does not end in a newline, so the last cut below would be the whole script")
	}
	cuts := map[int]bool{}
	for cut := 0; cut < complete; cut += 53 {
		cuts[cut] = true
	}
	for cut := complete - 200; cut < complete; cut++ {
		if cut >= 0 {
			cuts[cut] = true
		}
	}
	ordered := make([]int, 0, len(cuts))
	for cut := range cuts {
		ordered = append(ordered, cut)
	}
	sort.Ints(ordered)

	for _, shell := range pipeShells(t) {
		t.Run(strings.Join(shell, " "), func(t *testing.T) {
			stubs, log := pipeStubs(t)
			for _, cut := range ordered {
				ran, out, _ := pipeInto(t, shell, stubs, log, script[:cut], enrollArgs...)
				if ran != "" {
					from := cut - 40
					if from < 0 {
						from = 0
					}
					t.Fatalf("the installer cut off at byte %d of %d ran something.\n"+
						"  it ended in: %q\n  it ran: %q\n  output: %s",
						cut, len(script), script[from:cut], ran, out)
				}
			}
		})
	}
}

// The other half, without which the test above proves nothing: the whole
// script does run main, with its final newline and without it.
func TestTheWholeInstallerRunsMain(t *testing.T) {
	script := []byte(installerSource(t))
	for _, shell := range pipeShells(t) {
		t.Run(strings.Join(shell, " "), func(t *testing.T) {
			stubs, log := pipeStubs(t)
			for name, data := range map[string][]byte{
				"as shipped":                script,
				"without its final newline": script[:len(script)-1],
			} {
				ran, out, err := pipeInto(t, shell, stubs, log, data, enrollArgs...)
				if !strings.HasPrefix(ran, "id -u") {
					t.Errorf("%s: main did not run, the log reads %q\n%s", name, ran, out)
				}
				if err == nil || !strings.Contains(out, "run as root") {
					t.Errorf("%s: the script did not stop at its root check: %v\n%s", name, err, out)
				}
			}
		})
	}
}

// A download that failed outright: nothing arrives, nothing runs. The exit
// status is 0, the shell's, and that is harmless now that the command has
// nothing after the pipe. curl's own error is then the last line on the
// screen (measured in dash, bash and zsh against a name that does not
// resolve, 2026-10-02).
func TestAnEmptyDownloadRunsNothing(t *testing.T) {
	for _, shell := range pipeShells(t) {
		t.Run(strings.Join(shell, " "), func(t *testing.T) {
			stubs, log := pipeStubs(t)
			ran, out, err := pipeInto(t, shell, stubs, log, nil, enrollArgs...)
			if ran != "" {
				t.Errorf("an empty download ran something: %q", ran)
			}
			if out != "" {
				t.Errorf("an empty download printed something, which would sit under curl's error: %q", out)
			}
			if err != nil {
				t.Errorf("an empty script exited with %v, and a shell given nothing exits 0", err)
			}
		})
	}
}

// The cut-off test samples, so the shape it rests on is checked in full:
// outside main there is nothing that does anything. Above it only comments,
// `set -eu` and plain assignments, and below it only comments and the one
// braced call. A line added outside main later would run on a half download,
// and this is what says so.
func TestNothingRunsOutsideMain(t *testing.T) {
	lines := strings.Split(strings.TrimRight(installerSource(t), "\n"), "\n")

	open, closed := -1, -1
	for i, line := range lines {
		if line == "main() {" && open < 0 {
			open = i
		}
		// main's closing brace is the last one at the start of a line.
		if line == "}" {
			closed = i
		}
	}
	if open < 0 || closed < open {
		t.Fatalf("install.sh has no main() { ... } at the start of a line (open %d, close %d)", open, closed)
	}

	assignment := regexp.MustCompile(`^[A-Z_]+="[^"$` + "`" + `]*(\$[A-Z_]+[^"$` + "`" + `]*)*"$`)
	for i, line := range lines[:open] {
		switch {
		case line == "", strings.HasPrefix(line, "#"), line == "set -eu":
		case assignment.MatchString(line):
		default:
			t.Errorf("line %d, above main, is not a comment, set -eu or a plain "+
				"assignment, so it would run on a half download: %q", i+1, line)
		}
	}

	var after []string
	for _, line := range lines[closed+1:] {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		after = append(after, line)
	}
	if len(after) != 1 || after[0] != `{ main "$@"; }` {
		t.Errorf("below main there must be exactly the braced call `{ main \"$@\"; }`, found %q", after)
	}
	if last := lines[len(lines)-1]; last != `{ main "$@"; }` {
		t.Errorf("the last line of install.sh is %q, want the braced call", last)
	}
}

// What the installer accepts after `enroll` has to be what the agent's own
// enroll command takes, or the Add server window hands out a command the
// installer refuses. --allow-http is the one the installer leaves out on
// purpose: the agent calls it "Lab testing only", no command the control
// plane builds carries it, and an enrolment over plain http stays something
// a person types by hand.
func TestTheInstallerPassesOnExactlyTheAgentsEnrolFlags(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "cmd", "agent", "main.go"))
	if err != nil {
		t.Fatalf("reading the agent's main.go: %v", err)
	}
	start := bytes.Index(source, []byte("func runEnroll("))
	if start < 0 {
		t.Fatal("main.go has no runEnroll, so this test must be updated to match")
	}
	body := source[start:]
	if end := bytes.Index(body, []byte("\n}\n")); end > 0 {
		body = body[:end]
	}
	var agentFlags []string
	for _, match := range regexp.MustCompile(`fs\.(?:String|Bool)\("([a-z-]+)"`).FindAllSubmatch(body, -1) {
		if name := string(match[1]); name != "allow-http" {
			agentFlags = append(agentFlags, name)
		}
	}
	sort.Strings(agentFlags)
	if len(agentFlags) < 2 {
		t.Fatalf("read only %v from runEnroll, so this reader no longer matches the code", agentFlags)
	}

	script := installerSource(t)
	var installerFlags []string
	for _, match := range regexp.MustCompile(`--([a-z-]+)=\?\*`).FindAllStringSubmatch(script, -1) {
		installerFlags = append(installerFlags, match[1])
	}
	sort.Strings(installerFlags)

	if strings.Join(agentFlags, " ") != strings.Join(installerFlags, " ") {
		t.Errorf("the installer accepts %v after enroll, and the agent's enroll takes %v",
			installerFlags, agentFlags)
	}
	if !strings.Contains(script, `/usr/bin/whichports-agent enroll "$@"`) {
		t.Error("the installer does not hand its arguments to /usr/bin/whichports-agent enroll " +
			"by full path. Under sudo the PATH is the distribution's to set, which is the " +
			"fault of docs/RECORD.md 4.220")
	}
}

// With enroll, the installer does the three things the window's command used
// to chain after the pipe, in that order, and only inside the enroll branch:
// with no arguments it still starts nothing, which its header promises.
func TestOnlyTheEnrolBranchStartsAnything(t *testing.T) {
	script := installerSource(t)
	branch := strings.Index(script, `if [ "$ENROLL" = yes ]; then`)
	otherwise := strings.Index(script, "\nelse\n  echo\n  echo \"installed. Next steps:\"")
	if branch < 0 || otherwise < branch {
		t.Fatalf("install.sh has no enroll branch followed by the plain closing lines "+
			"(branch %d, else %d), so this test must be updated to match", branch, otherwise)
	}
	inBranch := script[branch:otherwise]
	enrol := strings.Index(inBranch, `/usr/bin/whichports-agent enroll "$@"`)
	enable := strings.Index(inBranch, "systemctl enable --now whichports-agent.timer")
	start := strings.Index(inBranch, "systemctl start whichports-agent.service")
	if enrol < 0 || enable < 0 || start < 0 {
		t.Fatalf("the enroll branch does not enrol, enable the timer and collect once: %d %d %d",
			enrol, enable, start)
	}
	if !(enrol < enable && enable < start) {
		t.Error("the enroll branch does its three steps out of order. Enrol first, so a " +
			"server that could not enrol never gets its timer turned on")
	}

	// Outside the branch, no line runs systemctl or the agent. Lines that
	// only print a next step for the operator are not calls.
	outside := script[:branch] + script[otherwise:]
	for _, line := range strings.Split(outside, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "echo ") {
			continue
		}
		if strings.HasPrefix(trimmed, "systemctl ") || strings.Contains(trimmed, "whichports-agent enroll") ||
			strings.HasPrefix(trimmed, "/usr/bin/whichports-agent") {
			t.Errorf("outside the enroll branch the installer runs %q, and with no "+
				"arguments it must start nothing", trimmed)
		}
	}
}

// The installer checks the credential's shape before it fetches anything,
// by the agent's own rule. On a real server, on 2026-10-02, the line with
// `--credential=hello` installed the package and only then had the
// enrolment refused (docs/RECORD.md 4.251): the installer checked that the
// flag was there and not what it held.
//
// The rule lives twice, in the agent's ValidateCredential and in the
// installer's credential_ok, because a shell script cannot call Go. This
// test is what keeps them one rule: every candidate is given to both, and
// they have to give the same answer.
func TestTheInstallerAndTheAgentAgreeOnACredentialsShape(t *testing.T) {
	a := func(n int) string { return strings.Repeat("a", n) }
	candidates := []string{
		// What the dashboard hands out: whp_ and 64 hex characters.
		"whp_" + strings.Repeat("0123456789abcdef", 4),
		// The edges of the length rule: 32 in the body, 128 in all.
		"whp_" + a(31), "whp_" + a(32), "whp_" + a(33),
		"whp_" + a(123), "whp_" + a(124), "whp_" + a(125),
		// Every kind of character the body may hold.
		"whp_" + a(28) + "AZ09", "whp_" + a(30) + "-_",
		// And ones it may not.
		"whp_" + a(31) + "!", "whp_" + a(31) + ".", "whp_" + a(31) + "/",
		"whp_" + a(31) + "=", "whp_" + a(31) + "+", "whp_" + a(31) + "*",
		"whp_" + a(31) + "?", "whp_" + a(16) + " " + a(16), "whp_" + a(31) + "\u00e9",
		"whp_" + a(31) + "$", "whp_" + a(16) + "'" + a(16), "whp_" + a(16) + `"` + a(16),
		// The prefix.
		"hello", "whp", "whp_", "WHP_" + a(40), "Whp_" + a(40), "whpp_" + a(64),
		"xwhp_" + a(40), " whp_" + a(40), a(40),
		// A pattern character where the prefix is, which a careless case
		// statement would take for a match.
		"*" + a(40), "?hp_" + a(40), "[w]hp_" + a(40),
	}

	for _, shell := range pipeShells(t) {
		t.Run(strings.Join(shell, " "), func(t *testing.T) {
			stubs, log := pipeStubs(t)
			script := []byte(installerSource(t))
			for _, candidate := range candidates {
				agentAccepts := report.ValidateCredential(candidate) == nil

				ran, out, err := pipeInto(t, shell, stubs, log, script,
					"enroll", "--server=https://app.example.invalid", "--credential="+candidate)
				// Accepted means the script got past its arguments to the
				// root check, which the stub `id` fails. Refused means it
				// stopped with status 2 and ran nothing.
				installerAccepts := strings.HasPrefix(ran, "id -u") && strings.Contains(out, "run as root")
				installerRefuses := ran == "" && strings.Contains(out, "the credential is not one the dashboard hands out")
				if exit, ok := err.(*exec.ExitError); installerRefuses && (!ok || exit.ExitCode() != 2) {
					t.Errorf("%q: the refusal did not exit with status 2: %v", candidate, err)
				}
				if installerAccepts == installerRefuses {
					t.Fatalf("%q: the installer neither accepted nor refused it cleanly.\n"+
						"  ran: %q\n  output: %s", candidate, ran, out)
				}
				if installerAccepts != agentAccepts {
					t.Errorf("%q: the agent accepts=%v and the installer accepts=%v. "+
						"One rule, two answers", candidate, agentAccepts, installerAccepts)
				}
				// A credential is a secret and a refusal is read aloud in
				// tickets and chats: it never repeats the value.
				if installerRefuses && len(candidate) > 4 && strings.Contains(out, candidate) {
					t.Errorf("the refusal prints the credential it refused: %s", out)
				}
			}
		})
	}
}

// With enroll, a package older than 0.1.12 has no agent in /usr/bin, and the
// line that enrols would end in the shell's own "No such file or directory",
// status 127, which is what the new installer met against the published
// 0.1.11 package on 2026-10-02 (docs/RECORD.md 4.251). The installer looks
// first and says so in plain words. The look has to come before the call.
func TestTheInstallerLooksForTheAgentBeforeItCallsIt(t *testing.T) {
	script := installerSource(t)
	look := strings.Index(script, "if [ ! -x /usr/bin/whichports-agent ]; then")
	call := strings.Index(script, `/usr/bin/whichports-agent enroll "$@"`)
	if look < 0 || call < 0 {
		t.Fatalf("install.sh does not look for the agent (%d) or does not call it (%d)", look, call)
	}
	if look > call {
		t.Error("install.sh calls /usr/bin/whichports-agent before it has looked whether it is there")
	}
	between := script[look:call]
	if !strings.Contains(between, "older than 0.1.12") || !strings.Contains(between, "exit 1") {
		t.Errorf("the look does not stop with a plain line about the older package:\n%s", between)
	}
}
