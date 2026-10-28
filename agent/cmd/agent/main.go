// Command agent is the whichports host collector. One binary, three run
// modes, and one offline enrollment command (docs/PRODUCT.md sections 4e
// and 4f):
//
//	--mode=stdout   read, print the document, send nothing off the machine.
//	                The default, and the way to evaluate the agent without
//	                trusting anything. It does not read the enrolment file,
//	                and the only connections it opens are local: one GET each
//	                to the Docker and Podman sockets, where they exist.
//	--mode=oneshot  read once and deliver the document to the control plane.
//	                For cron, Ansible or an RMM. Errors if the host is not
//	                enrolled, because someone asked for a report to be sent.
//	--mode=timer    the packaged systemd-timer mode. Writes the document to
//	                /var/lib/whichports/host.json atomically, then delivers
//	                it only when the host is enrolled. Un-enrolled, nothing
//	                leaves the machine and the timer is purely the local file.
//	enroll          write /etc/whichports/agent.conf from --server and
//	                --credential. No network involved: the dashboard generated
//	                the credential, this command only writes it down, readable
//	                by root and by the packaged unit's own user and nobody
//	                else (internal/report/enroll.go). A self-hosted control
//	                plane that uses whichports' probers adds --prober-server
//	                and --prober-proof-key, and the host then proves its
//	                public addresses to that server (claims.go).
//	--version       print one line naming the package version plus the commit,
//	                commit time and clean-or-modified state recorded at build
//	                time, then exit. Nothing is collected, nothing is sent.
//
// The delivery itself lives in internal/report, the one place in the agent
// allowed to speak HTTP to the network, and the safety tests keep it that way.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/whichports/whichports/agent/internal/collect"
	"github.com/whichports/whichports/agent/internal/hostdoc"
	"github.com/whichports/whichports/agent/internal/report"
)

// procRoot is where the collectors read the kernel's process and network
// state, and fsRoot is where the file-reading collectors resolve /etc and
// /usr/lib. Constants rather than flags because the agent always reads the
// real host in production; tests call the collectors directly with a fixture
// root.
const (
	procRoot = "/proc"
	fsRoot   = "/"
	// stateFile is where timer mode leaves the freshest document, whether or
	// not the host is enrolled. The packaging creates the directory 0750,
	// owned by the whichports-agent user the packaged unit runs as.
	stateFile = "/var/lib/whichports/host.json"
)

func main() {
	// `whichports-agent enroll ...` is a command, not a mode: it runs once,
	// by hand, and writes the config the reporting modes read.
	if len(os.Args) > 1 && os.Args[1] == "enroll" {
		if err := runEnroll(os.Args[2:], report.DefaultConfigPath, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "agent:", err)
			os.Exit(1)
		}
		return
	}
	showVersion := flag.Bool("version", false, "print one line saying what this binary is, then exit")
	mode := flag.String("mode", "stdout", "run mode: stdout, oneshot, or timer")
	flag.Parse()

	// --version returns here, before run() is ever called, so no collector
	// runs, nothing reads /proc and nothing can touch the network. The line
	// is built from the binary alone (cmd/agent/version.go), and the flag
	// package accepts it in any position: first, last, or among other flags.
	if *showVersion {
		printVersion(os.Stdout)
		return
	}

	if err := run(*mode, os.Stdout, time.Now().Unix(), report.DefaultConfigPath, stateFile); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
}

// run is separated from main so it is testable: the writer, the timestamp and
// both file paths are injected rather than taken from the process, keeping
// the clock, stdout and /etc out of the logic.
func run(mode string, out io.Writer, nowUnix int64, configPath, statePath string) error {
	switch mode {
	case "stdout":
		// stdout and oneshot write nothing on the host, so they name no
		// place to keep what the lists reader read.
		document, err := collectDocument(nowUnix, "")
		if err != nil {
			return err
		}
		_, err = out.Write(document)
		return err
	case "oneshot":
		document, err := collectDocument(nowUnix, "")
		if err != nil {
			return err
		}
		cfg, err := report.Load(configPath)
		if err != nil {
			// ErrNotEnrolled included: oneshot was asked to send, so an
			// un-enrolled host is an error here, with the fix in the message.
			return err
		}
		return deliver(report.NewClient(cfg), document)
	case "timer":
		// Timer mode is the one that writes on the host. A build with the
		// lists reader keeps what it read beside the state file, and every
		// other build names no such place (packages_on.go, packages_off.go).
		document, err := collectDocument(nowUnix, keptListsPath(statePath))
		if err != nil {
			return err
		}
		// The local file is written first and unconditionally, so the
		// freshest document is on disk even when the control plane is down.
		if err := writeFileAtomic(statePath, document); err != nil {
			return err
		}
		cfg, err := report.Load(configPath)
		if errors.Is(err, report.ErrNotEnrolled) {
			// Not enrolled is the packaged default, not a failure: this host
			// runs purely locally and nothing leaves the machine.
			return nil
		}
		if err != nil {
			return err
		}
		// A failed delivery is a real failure: the unit shows failed and the
		// journal says why, while the local file above stays fresh. The next
		// tick is the retry, and the control plane's silence sweep is what
		// notices a host that keeps failing.
		return deliver(report.NewClient(cfg), document)
	default:
		return fmt.Errorf("unknown mode %q, want stdout, oneshot, or timer", mode)
	}
}

// deliver sends the document, then says "this is me" once over each address
// family so a dual-stack host proves both of its addresses rather than only
// the one the report happened to travel over (docs/PRODUCT.md 5, the clause
// of 2026-09-18). A family the host has no route on fails to dial, which the
// client swallows: the report is what can fail a run, never the presence.
//
// On a host whose control plane uses our probers, the host's public addresses
// are proved to the prober API first (report.ProveToProber). First, so that
// on a new host the scan its control plane asks for when the first report
// lands finds the address already proved rather than refused. Nothing that
// happens there can fail the run either.
func deliver(client *report.Client, document []byte) error {
	ctx := context.Background()
	client.ProveToProber(ctx, claimedAddresses(document))
	if err := client.Send(ctx, document); err != nil {
		return err
	}
	client.ProveFamilies(ctx)
	return nil
}

// collectDocument builds and marshals the host document, newline terminated.
// Every mode reports exactly these bytes, so what stdout shows is what the
// control plane receives, byte for byte.
//
// keptLists is where the apt lists reader may keep what it read, or empty
// for a run that writes nothing on the host.
func collectDocument(nowUnix int64, keptLists string) ([]byte, error) {
	host, err := os.Hostname()
	if err != nil {
		// A missing hostname is not fatal to the document; record it empty
		// and carry on, because the collector's job is to report what it can.
		host = ""
	}
	// The hostname is host-provided text like any process name, and it goes
	// to the same terminal, so it follows the same sanitisation rule.
	doc := hostdoc.New(collect.SanitizeHostText(host), nowUnix)
	// Which binary produced this document. `version` is the same variable
	// --version prints, injected by the Makefile with -ldflags, so the
	// document, the binary and the package that ships it name one version.
	// Sanitised like any other text that reaches the wire and a terminal:
	// the value comes from our own build, but a locally built binary can
	// carry whatever was passed to -X and this field costs one call to be
	// certain rather than to assume.
	doc.AgentVersion = collect.SanitizeHostText(version)
	// Each collector fills its own section and never fails the run: a section
	// records its own read status, so one denied layer never blanks the rest.
	// The unit behind each socket comes from the kernel over sock_diag
	// netlink and the cgroup2 mount, joined on the socket inode, and costs
	// no capability (internal/collect/sockdiag.go). Linux only, like the
	// other netlink reads.
	doc.Sockets = collect.CollectSockets(procRoot, fsRoot, socketCgroups())
	// Socket units are read from unit files under fsRoot rather than from
	// /proc. They say which unit a socket-activated port belongs to, which
	// the process attribution above cannot: while the manager holds the
	// socket, even a root read of /proc names systemd rather than the
	// service that will actually be started.
	doc.SocketUnits = collect.CollectSocketUnits(fsRoot)
	// No root argument: this one reads the kernel over rtnetlink rather than a
	// file tree, because the kernel publishes no per-interface IPv4 address
	// list under /proc (internal/collect/interfaces.go).
	doc.InterfaceAddresses = collect.CollectInterfaceAddresses()
	doc.Nftables = collectNftables()
	doc.Ufw = collect.CollectUfw(fsRoot)
	doc.Firewalld = collect.CollectFirewalld(fsRoot)
	doc.RuleFiles = collect.CollectRuleFileMtimes(fsRoot)
	doc.Containers = collect.CollectContainers(fsRoot)
	doc.Iptables = collectIptables()
	doc.Ip6tables = collectIp6tables()
	doc.Overlays = collect.CollectOverlays(fsRoot)
	// Which package dpkg's records say owns the program behind each listening
	// service. It needs the two socket sections above to know which services
	// those are, so it runs after them (packages.go). Every build reads it
	// since 2026-10-12 (docs/SPEC-packages-switch.md).
	doc.Packages = collectPackages(fsRoot, doc.Sockets, doc.SocketUnits, keptLists)
	b, err := hostdoc.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// stateFileMode is what the host document is left as. The document lists
// every listening port on the box and the process behind each one, so it is
// not world-readable even though the 0750 state directory would already stop
// a stranger reading it. Two gates, because the directory's mode is set by a
// package script and this one is not.
const stateFileMode = 0o640

// writeFileAtomic writes via a temp file and rename in the same directory,
// so a reader of the state file never sees a half-written document. This is
// the same guarantee the packaged unit used to get from a shell redirect and
// mv; doing it here removes the shell from the unit entirely.
//
// The temp file is created by os.CreateTemp, which opens with O_EXCL and a
// name nobody can predict. The previous version wrote to a fixed "<path>.tmp"
// with plain O_CREATE, which a symlink already sitting at that name would
// have redirected: the process ran as root then, so it would have written the
// document wherever the link pointed. That needed write access to the state
// directory, which is root's, so it was never reachable in the packaged
// layout. It is fixed anyway, because "unreachable given the directory
// permissions" is a weaker thing to rely on than not being writable through
// a link at all.
func writeFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	// Named after the file it becomes: ".host.json.*" for the state file.
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	// Remove the temp file on every failure path below. After a successful
	// rename the name no longer exists, so the Remove is a harmless no-op.
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(stateFileMode); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// runEnroll parses `enroll --server=... --credential=... [--allow-http]
// [--prober-server=... --prober-proof-key=...]` and
// writes the config file. The credential comes from the dashboard's add-host
// screen and travels here in the operator's hands, never over this program's
// network: enrollment is a local file write and nothing else.
func runEnroll(args []string, configPath string, out io.Writer) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(out)
	server := fs.String("server", "", "control plane base URL, e.g. https://app.whichports.com")
	credential := fs.String("credential", "", "host credential shown once by the dashboard (whp_...)")
	allowHTTP := fs.Bool("allow-http", false, "permit a plain-http server URL. Lab testing only: the credential and the document travel unencrypted")
	proberServer := fs.String("prober-server", "", "whichports' prober API, when your control plane uses our probers. Given with --prober-proof-key")
	proofKey := fs.String("prober-proof-key", "", "the key that lets this host prove its addresses to the prober API (whpp_...)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" || *credential == "" {
		return errors.New("enroll needs both --server and --credential, the dashboard's add-host screen shows the exact command")
	}
	cfg := report.Config{Server: *server, Credential: *credential, AllowHTTP: *allowHTTP,
		ProberServer: *proberServer, ProofKey: *proofKey}
	if err := report.WriteConfig(configPath, cfg); err != nil {
		return err
	}
	// WriteConfig validated the URL, so this normalisation cannot fail now.
	normalised, _ := report.ValidateServer(*server, *allowHTTP)
	fmt.Fprintf(out, "enrolled: reports will be delivered to %s\n", normalised)
	if *proberServer != "" {
		prober, _ := report.ValidateProber(*proberServer, *proofKey, *allowHTTP)
		fmt.Fprintf(out, "and this host's public addresses will be proved to %s\n", prober)
	}
	fmt.Fprintln(out, "next: systemctl enable --now whichports-agent.timer  (or run --mode=oneshot from cron)")
	return nil
}
