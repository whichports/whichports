package collect

// The package collector's review.
//
// Where the fixtures come from. Every tree here is built by the test itself
// and none is a copy of a distribution's file. Their shape follows what was
// read on 2026-10-02 in Debian 12 and Ubuntu 24.04 containers with OpenSSH,
// nginx, MariaDB, Redis and PostgreSQL installed, and on Debian 13 and Ubuntu
// 26.04 for dpkg's own layout:
//
//	ssh.service    unit file and /usr/sbin/sshd both openssh-server, source
//	               openssh, the unit listed by dpkg as /lib/systemd/system
//	nginx.service  unit file nginx-common, /usr/sbin/nginx nginx, both from
//	               source nginx
//	redis-server   unit file and the link /usr/bin/redis-server both
//	               redis-server, the link's target redis-check-rdb
//	               redis-tools, all from source redis
//	postgresql@    unit file and /usr/bin/pg_ctlcluster, a script, both
//	               postgresql-common, while the server is postgresql-15, and
//	               ExecStart starts with the "-" prefix
//
// Re-read on 2026-10-03 by running this collector, as an unprivileged user,
// in Debian 12 and Ubuntu 24.04 containers with the five installed: every
// owner above is what it reported, the Redis link included.
//
// The versions are made up and look like Debian versions only so the parser
// meets an epoch and a revision. The program files hold four ELF magic bytes
// or a "#!" line and nothing else.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

const elfHead = "\x7fELF\x02\x01\x01\x00"

// pkgTree is a fake host: a merged-/usr layout, an os-release, dpkg's
// directory, and whatever the test adds.
type pkgTree struct {
	t      *testing.T
	root   string
	status []string
}

func newPkgTree(t *testing.T) *pkgTree {
	t.Helper()
	tr := &pkgTree{t: t, root: t.TempDir()}
	for _, d := range []string{"usr/bin", "usr/sbin", "usr/lib/systemd/system", "var/lib/dpkg/info", "etc/systemd/system"} {
		tr.dir(d)
	}
	tr.link("bin", "usr/bin")
	tr.link("sbin", "usr/sbin")
	tr.link("lib", "usr/lib")
	tr.file("usr/lib/os-release", "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\nID=debian\n")
	tr.link("etc/os-release", "../usr/lib/os-release")
	tr.file("var/lib/dpkg/diversions", "")
	tr.file("var/lib/dpkg/status", "")
	return tr
}

func (tr *pkgTree) dir(rel string) {
	tr.t.Helper()
	if err := os.MkdirAll(filepath.Join(tr.root, rel), 0o755); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr *pkgTree) file(rel, content string) {
	tr.t.Helper()
	tr.dir(filepath.Dir(rel))
	if err := os.WriteFile(filepath.Join(tr.root, rel), []byte(content), 0o644); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr *pkgTree) link(rel, target string) {
	tr.t.Helper()
	tr.dir(filepath.Dir(rel))
	if err := os.Symlink(target, filepath.Join(tr.root, rel)); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr *pkgTree) remove(rel string) {
	tr.t.Helper()
	if err := os.RemoveAll(filepath.Join(tr.root, rel)); err != nil {
		tr.t.Fatal(err)
	}
}

// deny makes a path unreadable, and puts it back when the test ends so
// t.TempDir can clean up.
func (tr *pkgTree) deny(rel string) {
	tr.t.Helper()
	p := filepath.Join(tr.root, rel)
	info, err := os.Stat(p)
	if err != nil {
		tr.t.Fatal(err)
	}
	if err := os.Chmod(p, 0); err != nil {
		tr.t.Fatal(err)
	}
	tr.t.Cleanup(func() { os.Chmod(p, info.Mode().Perm()) })
}

// pkg installs a package: its file list, and its stanza in the status file.
func (tr *pkgTree) pkg(list, stanza string, paths ...string) {
	tr.t.Helper()
	lines := append([]string{"/.", "/usr"}, paths...)
	tr.file("var/lib/dpkg/info/"+list+".list", strings.Join(lines, "\n")+"\n")
	if stanza != "" {
		tr.status = append(tr.status, stanza)
		tr.file("var/lib/dpkg/status", strings.Join(tr.status, "\n\n")+"\n")
	}
}

// unitFile writes a vendor unit file with one [Service] section.
func (tr *pkgTree) unitFile(name, service string) {
	tr.t.Helper()
	tr.file("usr/lib/systemd/system/"+name, "[Unit]\nDescription=a service\n\n[Service]\n"+service+"\n\n[Install]\nWantedBy=multi-user.target\n")
}

func (tr *pkgTree) collect(units ...string) *hostdoc.PackagesSection {
	tr.t.Helper()
	sec := CollectPackages(tr.root, units)
	mustMarshal(tr.t, sec)
	return sec
}

// mustMarshal holds every result to the document's own contract.
func mustMarshal(t *testing.T, sec *hostdoc.PackagesSection) []byte {
	t.Helper()
	d := hostdoc.New("h", 1)
	d.Packages = sec
	b, err := hostdoc.Marshal(d)
	if err != nil {
		t.Fatalf("the section failed the document contract: %v", err)
	}
	assertTerminalSafe(t, b)
	return b
}

func entry(t *testing.T, sec *hostdoc.PackagesSection, name string) hostdoc.UnitPackage {
	t.Helper()
	for _, u := range sec.Units {
		if u.Unit == name {
			return u
		}
	}
	t.Fatalf("no entry for %s in %+v", name, sec.Units)
	return hostdoc.UnitPackage{}
}

func ownerNamesOf(op *hostdoc.OwnedPath) []string {
	if op == nil {
		return nil
	}
	var out []string
	for _, o := range op.Owners {
		out = append(out, o.Name)
	}
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- the four

// sshHost is the OpenSSH shape: one package owns the unit file, under the
// /lib spelling, and the program.
func sshHost(t *testing.T) *pkgTree {
	tr := newPkgTree(t)
	tr.unitFile("ssh.service", "EnvironmentFile=-/etc/default/ssh\nExecStartPre=/usr/sbin/sshd -t\nExecStart=/usr/sbin/sshd -D $SSHD_OPTS --secret=hunter2\nExecReload=/usr/sbin/sshd -t")
	tr.file("usr/sbin/sshd", elfHead)
	tr.pkg("openssh-server",
		"Package: openssh-server\nStatus: install ok installed\nPriority: optional\nArchitecture: arm64\nMulti-Arch: foreign\nSource: openssh\nVersion: 1:9.0p1-1\nDescription: secure shell (SSH) server\n a long description\n .\n on several lines",
		"/lib/systemd/system/ssh.service", "/usr/sbin/sshd")
	return tr
}

func TestOpenSSHIsCompleteWithOneOwnerForBoth(t *testing.T) {
	sec := sshHost(t).collect("ssh.service")
	if sec.Status != hostdoc.StatusCollected {
		t.Fatalf("section status %q", sec.Status)
	}
	u := entry(t, sec, "ssh.service")
	if u.Finding != "complete" {
		t.Fatalf("finding %q", u.Finding)
	}
	if u.UnitFile.Path != "/usr/lib/systemd/system/ssh.service" {
		t.Errorf("unit file %q", u.UnitFile.Path)
	}
	if u.Program.Path != "/usr/sbin/sshd" || u.ProgramKind != "elf" {
		t.Errorf("program %q kind %q", u.Program.Path, u.ProgramKind)
	}
	if u.ProgramTarget != nil {
		t.Errorf("sshd is not a link, target %+v", u.ProgramTarget)
	}
	want := hostdoc.Package{Name: "openssh-server", Architecture: "arm64", Installed: true,
		Version: "1:9.0p1-1", Source: "openssh"}
	for _, op := range []*hostdoc.OwnedPath{u.UnitFile, u.Program} {
		if len(op.Owners) != 1 || op.Owners[0] != want {
			t.Errorf("%s owners %+v, want %+v", op.Path, op.Owners, want)
		}
		if op.Diverted {
			t.Errorf("%s reads diverted", op.Path)
		}
	}
}

func TestTheArgumentsNeverLeaveTheHost(t *testing.T) {
	b := mustMarshal(t, sshHost(t).collect("ssh.service"))
	for _, word := range []string{"hunter2", "--secret", "SSHD_OPTS", "-D"} {
		if strings.Contains(string(b), word) {
			t.Errorf("the document carries %q from ExecStart's arguments:\n%s", word, b)
		}
	}
}

func TestTheDistributionIsReadThroughTheRelativeLink(t *testing.T) {
	sec := sshHost(t).collect("ssh.service")
	want := hostdoc.Distribution{ID: "debian", VersionID: "12", VersionCodename: "bookworm"}
	if sec.Distribution == nil || *sec.Distribution != want {
		t.Fatalf("distribution %+v", sec.Distribution)
	}
	if sec.Sources["os_release"].Status != hostdoc.StatusCollected {
		t.Errorf("os_release %+v", sec.Sources["os_release"])
	}
}

func TestNginxNamesTwoPackagesOfOneSource(t *testing.T) {
	tr := newPkgTree(t)
	tr.unitFile("nginx.service", "Type=forking\nExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'\nExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'")
	tr.file("usr/sbin/nginx", elfHead)
	tr.pkg("nginx-common", "Package: nginx-common\nStatus: install ok installed\nArchitecture: all\nSource: nginx\nVersion: 1.22.1-9", "/lib/systemd/system/nginx.service")
	tr.pkg("nginx", "Package: nginx\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1.22.1-9", "/usr/sbin/nginx")
	u := entry(t, tr.collect("nginx.service"), "nginx.service")
	if u.Finding != "complete" {
		t.Fatalf("finding %q", u.Finding)
	}
	if got := ownerNamesOf(u.UnitFile); !sameStrings(got, []string{"nginx-common"}) {
		t.Errorf("unit file owners %v", got)
	}
	if u.UnitFile.Owners[0].Source != "nginx" {
		t.Errorf("nginx-common source %q", u.UnitFile.Owners[0].Source)
	}
	// nginx's stanza has no Source field, which deb-control(5) says means
	// its own name. The field is carried as written, empty.
	p := u.Program.Owners
	if len(p) != 1 || p[0].Name != "nginx" || p[0].Source != "" || p[0].Version != "1.22.1-9" {
		t.Errorf("program owners %+v", p)
	}
}

func TestRedisProgramIsALinkAndBothEndsAreOwned(t *testing.T) {
	tr := newPkgTree(t)
	tr.unitFile("redis-server.service", "Type=notify\nExecStart=/usr/bin/redis-server /etc/redis/redis.conf --supervised systemd --daemonize no")
	tr.file("usr/bin/redis-check-rdb", elfHead)
	tr.link("usr/bin/redis-server", "redis-check-rdb")
	tr.pkg("redis-server", "Package: redis-server\nStatus: install ok installed\nArchitecture: arm64\nSource: redis\nVersion: 5:7.0.0-1", "/lib/systemd/system/redis-server.service", "/usr/bin/redis-server")
	tr.pkg("redis-tools", "Package: redis-tools\nStatus: install ok installed\nArchitecture: arm64\nSource: redis\nVersion: 5:7.0.0-1", "/usr/bin/redis-check-rdb")
	u := entry(t, tr.collect("redis-server.service"), "redis-server.service")
	if u.Finding != "complete" {
		t.Fatalf("finding %q", u.Finding)
	}
	if u.Program.Path != "/usr/bin/redis-server" || u.ProgramKind != "elf" {
		t.Errorf("program %q kind %q, the kind is read through the link", u.Program.Path, u.ProgramKind)
	}
	if u.ProgramTarget == nil || u.ProgramTarget.Path != "/usr/bin/redis-check-rdb" {
		t.Fatalf("target %+v", u.ProgramTarget)
	}
	// The link is redis-server's and the program it leads to is
	// redis-tools', which is why both ends are reported.
	if got := ownerNamesOf(u.ProgramTarget); !sameStrings(got, []string{"redis-tools"}) {
		t.Errorf("target owners %v", got)
	}
	for _, op := range []*hostdoc.OwnedPath{u.UnitFile, u.Program} {
		if got := ownerNamesOf(op); !sameStrings(got, []string{"redis-server"}) {
			t.Errorf("%s owners %v", op.Path, got)
		}
	}
}

func TestPostgresqlInstanceReadsItsTemplateAndNamesNoProgram(t *testing.T) {
	// Its ExecStart starts with "-", so no program is named, and the unit
	// file's owner is postgresql-common, not the server's package.
	tr := newPkgTree(t)
	tr.unitFile("postgresql@.service", "Type=forking\nExecStart=-/usr/bin/pg_ctlcluster --skip-systemctl-redirect %i start")
	tr.file("usr/bin/pg_ctlcluster", "#!/usr/bin/perl -wT\n")
	tr.pkg("postgresql-common", "Package: postgresql-common\nStatus: install ok installed\nArchitecture: all\nVersion: 248", "/lib/systemd/system/postgresql@.service", "/usr/bin/pg_ctlcluster")
	u := entry(t, tr.collect("postgresql@15-main.service"), "postgresql@15-main.service")
	if u.Finding != "exec_start_prefixed" || u.Program != nil {
		t.Fatalf("%+v", u)
	}
	if u.UnitFile.Path != "/usr/lib/systemd/system/postgresql@.service" {
		t.Errorf("the instance should load its template, read %q", u.UnitFile.Path)
	}
	if got := ownerNamesOf(u.UnitFile); !sameStrings(got, []string{"postgresql-common"}) {
		t.Errorf("unit file owners %v", got)
	}
}

func TestAScriptProgramIsNamedAsAScript(t *testing.T) {
	// The same unit without the prefix: the program is named and its kind is
	// script, which the control plane's rule refuses on its own.
	tr := newPkgTree(t)
	tr.unitFile("postgresql@.service", "Type=forking\nExecStart=/usr/bin/pg_ctlcluster --skip-systemctl-redirect %i start")
	tr.file("usr/bin/pg_ctlcluster", "#!/usr/bin/perl -wT\n")
	u := entry(t, tr.collect("postgresql@15-main.service"), "postgresql@15-main.service")
	if u.Finding != "complete" || u.ProgramKind != "script" {
		t.Fatalf("finding %q kind %q", u.Finding, u.ProgramKind)
	}
	if strings.Contains(string(mustMarshal(t, tr.collect("postgresql@15-main.service"))), "%i") {
		t.Error("an argument with a specifier reached the document")
	}
}

// --------------------------------------------------------- the unit file

func TestALiteralInstanceFileBeatsTheTemplateEvenFurtherDown(t *testing.T) {
	tr := newPkgTree(t)
	tr.file("etc/systemd/system/app@.service", "[Service]\nExecStart=/usr/bin/template\n")
	tr.unitFile("app@one.service", "ExecStart=/usr/bin/literal")
	u := entry(t, tr.collect("app@one.service"), "app@one.service")
	if u.UnitFile.Path != "/usr/lib/systemd/system/app@one.service" || u.Program.Path != "/usr/bin/literal" {
		t.Errorf("read %q starting %+v", u.UnitFile.Path, u.Program)
	}
}

func TestAnAdministratorsCopyShadowsTheVendorFileAndHasNoOwner(t *testing.T) {
	tr := sshHost(t)
	tr.file("etc/systemd/system/ssh.service", "[Service]\nExecStart=/usr/sbin/sshd -D\n")
	u := entry(t, tr.collect("ssh.service"), "ssh.service")
	if u.UnitFile.Path != "/etc/systemd/system/ssh.service" {
		t.Fatalf("unit file %q, /etc comes first in the load path", u.UnitFile.Path)
	}
	if len(u.UnitFile.Owners) != 0 {
		t.Errorf("a hand-written unit file reads owners %+v", u.UnitFile.Owners)
	}
	if got := ownerNamesOf(u.Program); !sameStrings(got, []string{"openssh-server"}) {
		t.Errorf("program owners %v", got)
	}
}

func TestAUnitWithNoFileSaysSo(t *testing.T) {
	u := entry(t, sshHost(t).collect("transient.service"), "transient.service")
	if u.Finding != "no_unit_file" || u.UnitFile != nil || u.Program != nil {
		t.Errorf("%+v", u)
	}
}

func TestAUnitFileThatCannotBeTakenAtItsWordIsNotRead(t *testing.T) {
	cases := map[string]func(tr *pkgTree){
		"a symbolic link": func(tr *pkgTree) {
			tr.remove("usr/lib/systemd/system/ssh.service")
			tr.file("opt/ssh.service", "[Service]\nExecStart=/usr/sbin/sshd\n")
			tr.link("usr/lib/systemd/system/ssh.service", "../../../../opt/ssh.service")
		},
		"masked by being empty": func(tr *pkgTree) {
			tr.file("usr/lib/systemd/system/ssh.service", "")
		},
		"masked by a link to /dev/null": func(tr *pkgTree) {
			tr.file("etc/systemd/system/.keep", "")
			tr.link("etc/systemd/system/ssh.service", "/dev/null")
		},
		"a directory": func(tr *pkgTree) {
			tr.dir("etc/systemd/system/ssh.service")
		},
		"past the size cap": func(tr *pkgTree) {
			tr.file("usr/lib/systemd/system/ssh.service", "[Service]\nExecStart=/usr/sbin/sshd\n"+strings.Repeat("#", ufwFileLimit))
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			tr := sshHost(t)
			change(tr)
			u := entry(t, tr.collect("ssh.service"), "ssh.service")
			if u.Finding != "unit_file_not_read" || u.Program != nil {
				t.Errorf("%+v", u)
			}
			if u.UnitFile == nil {
				t.Error("the file was found, so its path is reported")
			}
		})
	}
}

func TestAUnitFileAtTheSizeCapIsRead(t *testing.T) {
	tr := sshHost(t)
	head := "[Service]\nExecStart=/usr/sbin/sshd\n"
	tr.file("usr/lib/systemd/system/ssh.service", head+strings.Repeat("#", ufwFileLimit-len(head)))
	if u := entry(t, tr.collect("ssh.service"), "ssh.service"); u.Finding != "complete" {
		t.Errorf("finding %q", u.Finding)
	}
}

func TestAnUnreadableUnitFileIsNotRead(t *testing.T) {
	skipIfRoot(t)
	tr := sshHost(t)
	tr.deny("usr/lib/systemd/system/ssh.service")
	if u := entry(t, tr.collect("ssh.service"), "ssh.service"); u.Finding != "unit_file_not_read" {
		t.Errorf("finding %q", u.Finding)
	}
}

func TestAUnitDirectoryThatCannotBeSearchedHidesTheAnswer(t *testing.T) {
	skipIfRoot(t)
	tr := sshHost(t)
	// /etc/systemd/system outranks the vendor directory, so not being able
	// to look in it means the vendor file may not be the one systemd loads.
	tr.deny("etc/systemd/system")
	u := entry(t, tr.collect("ssh.service"), "ssh.service")
	if u.Finding != "unit_file_not_read" || u.UnitFile != nil {
		t.Errorf("%+v", u)
	}
}

// ------------------------------------------------------------- ExecStart=

func TestExecStartFindings(t *testing.T) {
	cases := []struct {
		name, service, finding, program string
	}{
		{"one plain path", "ExecStart=/usr/sbin/sshd -D", "complete", "/usr/sbin/sshd"},
		{"spaces around the equals sign", "ExecStart = /usr/sbin/sshd", "complete", "/usr/sbin/sshd"},
		{"a continued line", "ExecStart=/usr/sbin/sshd \\\n  -D -e", "complete", "/usr/sbin/sshd"},
		{"a reset, then one", "ExecStart=/usr/bin/first\nExecStart=\nExecStart=/usr/sbin/sshd", "complete", "/usr/sbin/sshd"},
		{"none", "Type=oneshot\nRemainAfterExit=yes\nExecStop=/usr/bin/stop", "no_exec_start", ""},
		{"reset to nothing", "ExecStart=/usr/sbin/sshd\nExecStart=", "no_exec_start", ""},
		{"only in [Unit]", "", "no_exec_start", ""},
		{"two lines", "Type=oneshot\nExecStart=/usr/bin/a\nExecStart=/usr/bin/b", "several_exec_start", ""},
		{"two commands on one line", "Type=oneshot\nExecStart=/usr/bin/a ; /usr/bin/b", "several_exec_start", ""},
		{"an escaped semicolon is an argument", "ExecStart=/usr/bin/find . \\; -print", "complete", "/usr/bin/find"},
		{"a semicolon inside a word is an argument", "ExecStart=/usr/sbin/nginx -g daemon;", "complete", "/usr/sbin/nginx"},
		{"prefix @", "ExecStart=@/usr/sbin/sshd sshd -D", "exec_start_prefixed", ""},
		{"prefix -", "ExecStart=-/usr/sbin/sshd", "exec_start_prefixed", ""},
		{"prefix :", "ExecStart=:/usr/sbin/sshd", "exec_start_prefixed", ""},
		{"prefix +", "ExecStart=+/usr/sbin/sshd", "exec_start_prefixed", ""},
		{"prefix !", "ExecStart=!/usr/sbin/sshd", "exec_start_prefixed", ""},
		{"prefix !!", "ExecStart=!!/usr/sbin/sshd", "exec_start_prefixed", ""},
		{"a bare file name", "ExecStart=sshd -D", "exec_start_not_a_path", ""},
		{"a relative path", "ExecStart=bin/sshd", "exec_start_not_a_path", ""},
		{"quoted", "ExecStart=\"/opt/my app/run\"", "exec_start_not_a_path", ""},
		{"single quoted", "ExecStart='/usr/sbin/sshd'", "exec_start_not_a_path", ""},
		{"a specifier", "ExecStart=/opt/%i/run", "exec_start_not_a_path", ""},
		{"a variable", "ExecStart=${DAEMON} -D", "exec_start_not_a_path", ""},
		{"a variable inside the path", "ExecStart=/opt/$APP/run", "exec_start_not_a_path", ""},
		{"an escape", "ExecStart=/usr/sbin/ss\\x68d", "exec_start_not_a_path", ""},
		{"a doubled slash", "ExecStart=//usr/sbin/sshd", "exec_start_not_a_path", ""},
		{"a dot dot", "ExecStart=/usr/bin/../sbin/sshd", "exec_start_not_a_path", ""},
		{"a trailing slash", "ExecStart=/usr/sbin/", "exec_start_not_a_path", ""},
		{"the root", "ExecStart=/", "exec_start_not_a_path", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := newPkgTree(t)
			tr.unitFile("app.service", c.service)
			if c.name == "only in [Unit]" {
				tr.file("usr/lib/systemd/system/app.service", "[Unit]\nExecStart=/usr/sbin/sshd\n[Service]\nType=simple\n")
			}
			u := entry(t, tr.collect("app.service"), "app.service")
			if u.Finding != c.finding {
				t.Fatalf("finding %q, want %q", u.Finding, c.finding)
			}
			got := ""
			if u.Program != nil {
				got = u.Program.Path
			}
			if got != c.program {
				t.Errorf("program %q, want %q", got, c.program)
			}
		})
	}
}

func TestAProgramPathPastTheCapIsCut(t *testing.T) {
	long := "/opt/" + strings.Repeat("a", hostdoc.MaxPackagePathLen)
	tr := newPkgTree(t)
	tr.unitFile("app.service", "ExecStart="+long)
	u := entry(t, tr.collect("app.service"), "app.service")
	if u.Finding != "over_cap" || u.Program != nil {
		t.Errorf("%+v", u)
	}
}

func TestAPathThatGrowsWhenMadeSafeIsMeasuredAsSent(t *testing.T) {
	// 200 bytes that are not UTF-8 become 600 once each is the replacement
	// character, so a path under the cap as read is over it as sent. Found by
	// FuzzExecStartProgram: measured raw, it reached the marshaller and failed
	// the whole report.
	tr := newPkgTree(t)
	tr.unitFile("app.service", "ExecStart=/opt/"+strings.Repeat("\x9d", 200))
	u := entry(t, tr.collect("app.service"), "app.service")
	if u.Finding != "over_cap" || u.Program != nil {
		t.Errorf("%+v", u)
	}
}

func TestAProgramPathAtTheCapIsKept(t *testing.T) {
	path := "/opt/" + strings.Repeat("a", hostdoc.MaxPackagePathLen-len("/opt/"))
	tr := newPkgTree(t)
	tr.unitFile("app.service", "ExecStart="+path)
	u := entry(t, tr.collect("app.service"), "app.service")
	if u.Program == nil || u.Program.Path != path {
		t.Errorf("%+v", u)
	}
}

// ---------------------------------------------------------------- drop-ins

func TestADropInThatSetsExecStartLeavesNoProgram(t *testing.T) {
	cases := map[string]string{
		"its own directory in /etc":         "etc/systemd/system/ssh.service.d/override.conf",
		"its own directory in /run":         "run/systemd/system/ssh.service.d/override.conf",
		"its own directory in the vendor's": "usr/lib/systemd/system/ssh.service.d/override.conf",
		"a generator's directory":           "run/systemd/generator/ssh.service.d/override.conf",
		"the top-level service.d":           "etc/systemd/system/service.d/all.conf",
		"a dashed prefix":                   "etc/systemd/system/ss-.service.d/x.conf",
		"an alias's directory":              "etc/systemd/system/sshd.service.d/override.conf",
	}
	for name, rel := range cases {
		t.Run(name, func(t *testing.T) {
			tr := sshHost(t)
			if name == "a dashed prefix" {
				tr.unitFile("ss-h.service", "ExecStart=/usr/sbin/sshd")
			}
			// Debian's sshd.service is a link that makes it another name for
			// ssh.service, and an alias's drop-ins apply (systemd.unit(5)).
			tr.link("etc/systemd/system/sshd.service", "/lib/systemd/system/ssh.service")
			tr.file(rel, "[Service]\nExecStart=\nExecStart=/opt/other/sshd -D\n")
			unit := "ssh.service"
			if name == "a dashed prefix" {
				unit = "ss-h.service"
			}
			u := entry(t, tr.collect(unit), unit)
			if u.Finding != "drop_in_sets_exec_start" || u.Program != nil {
				t.Errorf("%+v", u)
			}
		})
	}
}

func TestATemplatesDropInAppliesToItsInstance(t *testing.T) {
	tr := newPkgTree(t)
	tr.unitFile("app@.service", "ExecStart=/usr/bin/app %i")
	tr.file("etc/systemd/system/app@.service.d/x.conf", "[Service]\nExecStart=\nExecStart=/usr/bin/other\n")
	if u := entry(t, tr.collect("app@one.service"), "app@one.service"); u.Finding != "drop_in_sets_exec_start" {
		t.Errorf("finding %q", u.Finding)
	}
}

func TestADropInThatLeavesExecStartAloneChangesNothing(t *testing.T) {
	tr := sshHost(t)
	tr.file("etc/systemd/system/ssh.service.d/restart.conf", "[Service]\nRestart=always\n# ExecStart=/opt/commented/out\n")
	tr.file("etc/systemd/system/ssh.service.d/notes.txt", "ExecStart=/not/a/conf/file\n")
	tr.file("etc/systemd/system/other.service.d/x.conf", "[Service]\nExecStart=/opt/another/unit\n")
	if u := entry(t, tr.collect("ssh.service"), "ssh.service"); u.Finding != "complete" {
		t.Errorf("finding %q", u.Finding)
	}
}

func TestADropInThatCannotBeReadHidesTheProgram(t *testing.T) {
	skipIfRoot(t)
	tr := sshHost(t)
	tr.file("etc/systemd/system/ssh.service.d/secret.conf", "[Service]\nRestart=always\n")
	tr.deny("etc/systemd/system/ssh.service.d/secret.conf")
	if u := entry(t, tr.collect("ssh.service"), "ssh.service"); u.Finding != "drop_in_not_read" {
		t.Errorf("finding %q", u.Finding)
	}
}

func TestADropInPastTheSizeCapHidesTheProgram(t *testing.T) {
	tr := sshHost(t)
	tr.file("etc/systemd/system/ssh.service.d/big.conf", strings.Repeat("#", ufwFileLimit+1))
	if u := entry(t, tr.collect("ssh.service"), "ssh.service"); u.Finding != "drop_in_not_read" {
		t.Errorf("finding %q", u.Finding)
	}
}

// ---------------------------------------------------------- program kinds

func TestProgramKinds(t *testing.T) {
	cases := map[string]struct {
		make func(tr *pkgTree)
		want string
	}{
		"compiled":        {func(tr *pkgTree) { tr.file("usr/bin/app", elfHead) }, "elf"},
		"a script":        {func(tr *pkgTree) { tr.file("usr/bin/app", "#!/bin/sh\nexec true\n") }, "script"},
		"text":            {func(tr *pkgTree) { tr.file("usr/bin/app", "plain text") }, "other"},
		"empty":           {func(tr *pkgTree) { tr.file("usr/bin/app", "") }, "other"},
		"one byte":        {func(tr *pkgTree) { tr.file("usr/bin/app", "#") }, "other"},
		"missing":         {func(tr *pkgTree) {}, "not_read"},
		"a directory":     {func(tr *pkgTree) { tr.dir("usr/bin/app") }, "not_read"},
		"a dangling link": {func(tr *pkgTree) { tr.link("usr/bin/app", "gone") }, "not_read"},
		"a FIFO": {func(tr *pkgTree) {
			if err := syscall.Mkfifo(filepath.Join(tr.root, "usr/bin/app"), 0o644); err != nil {
				tr.t.Skip("no FIFO here:", err)
			}
		}, "not_read"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tr := newPkgTree(t)
			tr.unitFile("app.service", "ExecStart=/usr/bin/app")
			c.make(tr)
			u := entry(t, tr.collect("app.service"), "app.service")
			if u.Finding != "complete" || u.ProgramKind != c.want {
				t.Errorf("finding %q kind %q, want complete and %q", u.Finding, u.ProgramKind, c.want)
			}
		})
	}
}

func TestAnUnreadableProgramIsNotRead(t *testing.T) {
	skipIfRoot(t)
	tr := newPkgTree(t)
	tr.unitFile("app.service", "ExecStart=/usr/bin/app")
	tr.file("usr/bin/app", elfHead)
	tr.deny("usr/bin/app")
	if u := entry(t, tr.collect("app.service"), "app.service"); u.ProgramKind != "not_read" {
		t.Errorf("kind %q", u.ProgramKind)
	}
}

func TestALinkChainIsFollowedToItsEnd(t *testing.T) {
	tr := newPkgTree(t)
	tr.unitFile("app.service", "ExecStart=/usr/bin/app")
	tr.file("usr/lib/app/real", elfHead)
	tr.link("usr/bin/middle", "../lib/app/real")
	tr.link("usr/bin/app", "middle")
	u := entry(t, tr.collect("app.service"), "app.service")
	if u.ProgramTarget == nil || u.ProgramTarget.Path != "/usr/lib/app/real" || u.ProgramKind != "elf" {
		t.Errorf("%+v kind %q", u.ProgramTarget, u.ProgramKind)
	}
}

func TestALinkLoopLeadsNowhere(t *testing.T) {
	tr := newPkgTree(t)
	tr.unitFile("app.service", "ExecStart=/usr/bin/app")
	tr.link("usr/bin/app", "loop")
	tr.link("usr/bin/loop", "app")
	u := entry(t, tr.collect("app.service"), "app.service")
	if u.ProgramTarget != nil || u.ProgramKind != "not_read" {
		t.Errorf("%+v kind %q", u.ProgramTarget, u.ProgramKind)
	}
}

// -------------------------------------------------- dpkg's files and owners

func TestTheOtherSpellingIsTriedOnlyOnAMergedHost(t *testing.T) {
	build := func(t *testing.T, merged bool) *hostdoc.PackagesSection {
		tr := newPkgTree(t)
		if !merged {
			tr.remove("bin")
			tr.dir("bin")
		}
		tr.unitFile("app.service", "ExecStart=/usr/bin/app")
		tr.file("usr/bin/app", elfHead)
		tr.pkg("app", "Package: app\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1.0-1", "/bin/app")
		return tr.collect("app.service")
	}
	if got := ownerNamesOf(entry(t, build(t, true), "app.service").Program); !sameStrings(got, []string{"app"}) {
		t.Errorf("merged host: owners %v", got)
	}
	if got := ownerNamesOf(entry(t, build(t, false), "app.service").Program); len(got) != 0 {
		t.Errorf("a host that is not merged must not read /bin/app as /usr/bin/app: owners %v", got)
	}
}

func TestAProgramInstalledByHandHasNoOwner(t *testing.T) {
	tr := sshHost(t)
	tr.unitFile("custom.service", "ExecStart=/usr/local/bin/custom")
	tr.file("usr/local/bin/custom", elfHead)
	u := entry(t, tr.collect("custom.service"), "custom.service")
	if u.Finding != "complete" || len(u.Program.Owners) != 0 || len(u.UnitFile.Owners) != 0 {
		t.Errorf("%+v", u)
	}
}

func TestADivertedPathReadsDiverted(t *testing.T) {
	tr := sshHost(t)
	tr.file("var/lib/dpkg/diversions", "/bin/sh\n/bin/sh.distrib\ndash\n/usr/sbin/sshd\n/usr/sbin/sshd.distrib\n:\n")
	u := entry(t, tr.collect("ssh.service"), "ssh.service")
	if !u.Program.Diverted {
		t.Error("sshd is diverted by the administrator and reads as not diverted")
	}
	if u.UnitFile.Diverted {
		t.Error("the unit file is not diverted")
	}
}

func TestADiversionUnderTheOtherSpellingCounts(t *testing.T) {
	tr := sshHost(t)
	tr.file("var/lib/dpkg/diversions", "/sbin/sshd\n/sbin/sshd.distrib\n:\n")
	if !entry(t, tr.collect("ssh.service"), "ssh.service").Program.Diverted {
		t.Error("/sbin/sshd is /usr/sbin/sshd on a merged host")
	}
}

func TestDiversionsThatCannotBeKnownListNoUnits(t *testing.T) {
	cases := map[string]func(tr *pkgTree){
		"malformed, not three lines each": func(tr *pkgTree) {
			tr.file("var/lib/dpkg/diversions", "/usr/sbin/sshd\n/usr/sbin/sshd.distrib\n")
		},
		"past the size cap": func(tr *pkgTree) {
			triple := "/a\n/b\n:\n"
			tr.file("var/lib/dpkg/diversions", strings.Repeat(triple, ufwFileLimit/len(triple)+1))
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			tr := sshHost(t)
			change(tr)
			sec := tr.collect("ssh.service")
			if len(sec.Units) != 0 {
				t.Errorf("units listed with unknown diversions: %+v", sec.Units)
			}
			if sec.Sources["dpkg_diversions"].Status != hostdoc.StatusReadError {
				t.Errorf("dpkg_diversions %+v", sec.Sources["dpkg_diversions"])
			}
		})
	}
}

func TestNoDiversionsFileIsNoDiversions(t *testing.T) {
	tr := sshHost(t)
	tr.remove("var/lib/dpkg/diversions")
	sec := tr.collect("ssh.service")
	if entry(t, sec, "ssh.service").Finding != "complete" {
		t.Errorf("%+v", sec.Units)
	}
	if sec.Sources["dpkg_diversions"].Status != hostdoc.StatusNotPresent {
		t.Errorf("dpkg_diversions %+v", sec.Sources["dpkg_diversions"])
	}
}

func TestAnUnreadableDiversionsFileListsNoUnits(t *testing.T) {
	skipIfRoot(t)
	tr := sshHost(t)
	tr.deny("var/lib/dpkg/diversions")
	sec := tr.collect("ssh.service")
	if len(sec.Units) != 0 || sec.Sources["dpkg_diversions"].Status != hostdoc.StatusPermissionDenied {
		t.Errorf("units %+v diversions %+v", sec.Units, sec.Sources["dpkg_diversions"])
	}
}

func TestAHostWithoutDpkgReadsNotPresent(t *testing.T) {
	tr := sshHost(t)
	tr.remove("var/lib/dpkg")
	sec := tr.collect("ssh.service")
	if sec.Status != hostdoc.StatusNotPresent || len(sec.Units) != 0 {
		t.Errorf("status %q units %+v", sec.Status, sec.Units)
	}
	for _, key := range []string{"dpkg_status", "dpkg_info", "dpkg_diversions"} {
		if sec.Sources[key].Status != hostdoc.StatusNotPresent {
			t.Errorf("%s %+v", key, sec.Sources[key])
		}
	}
	// The distribution is still read: a host of the RHEL family says which
	// one it is even though no package can be named on it yet.
	if sec.Distribution == nil || sec.Distribution.ID != "debian" {
		t.Errorf("distribution %+v", sec.Distribution)
	}
}

func TestAnUnreadableInfoDirectoryListsNoUnits(t *testing.T) {
	skipIfRoot(t)
	tr := sshHost(t)
	tr.deny("var/lib/dpkg/info")
	sec := tr.collect("ssh.service")
	if len(sec.Units) != 0 || sec.Sources["dpkg_info"].Status != hostdoc.StatusPermissionDenied {
		t.Errorf("units %+v info %+v", sec.Units, sec.Sources["dpkg_info"])
	}
}

func TestOneUnreadableFileListListsNoUnits(t *testing.T) {
	skipIfRoot(t)
	tr := sshHost(t)
	tr.pkg("other", "Package: other\nStatus: install ok installed\nArchitecture: all\nVersion: 1", "/usr/share/other")
	tr.deny("var/lib/dpkg/info/other.list")
	sec := tr.collect("ssh.service")
	if len(sec.Units) != 0 || sec.Sources["dpkg_info"].Status != hostdoc.StatusPermissionDenied {
		t.Errorf("units %+v info %+v", sec.Units, sec.Sources["dpkg_info"])
	}
}

func TestAFileListPastItsCapListsNoUnits(t *testing.T) {
	tr := sshHost(t)
	saved := maxListBytes
	maxListBytes = 64
	t.Cleanup(func() { maxListBytes = saved })
	tr.pkg("big", "", "/usr/share/"+strings.Repeat("x", 80))
	sec := tr.collect("ssh.service")
	if len(sec.Units) != 0 || sec.Sources["dpkg_info"].Status != hostdoc.StatusReadError {
		t.Errorf("units %+v info %+v", sec.Units, sec.Sources["dpkg_info"])
	}
}

func TestFileListsPastTheirTotalCapListNoUnits(t *testing.T) {
	tr := sshHost(t)
	saved := maxListTotalBytes
	maxListTotalBytes = 10
	t.Cleanup(func() { maxListTotalBytes = saved })
	sec := tr.collect("ssh.service")
	if len(sec.Units) != 0 || sec.Sources["dpkg_info"].Status != hostdoc.StatusReadError {
		t.Errorf("units %+v info %+v", sec.Units, sec.Sources["dpkg_info"])
	}
}

func TestAFileListAtItsCapIsRead(t *testing.T) {
	tr := sshHost(t)
	content, err := os.ReadFile(filepath.Join(tr.root, "var/lib/dpkg/info/openssh-server.list"))
	if err != nil {
		t.Fatal(err)
	}
	saved := maxListBytes
	maxListBytes = len(content)
	t.Cleanup(func() { maxListBytes = saved })
	if u := entry(t, tr.collect("ssh.service"), "ssh.service"); len(u.Program.Owners) != 1 {
		t.Errorf("%+v", u)
	}
}

func TestAMissingStatusFileLeavesOwnersWithNamesOnly(t *testing.T) {
	tr := sshHost(t)
	tr.remove("var/lib/dpkg/status")
	sec := tr.collect("ssh.service")
	if sec.Status != hostdoc.StatusCollected || sec.Sources["dpkg_status"].Status != hostdoc.StatusNotPresent {
		t.Fatalf("status %q, dpkg_status %+v", sec.Status, sec.Sources["dpkg_status"])
	}
	o := entry(t, sec, "ssh.service").Program.Owners
	if len(o) != 1 || o[0] != (hostdoc.Package{Name: "openssh-server"}) {
		t.Errorf("owners %+v, want the name and nothing the status file would have said", o)
	}
}

func TestAStatusFilePastItsCapIsARefusal(t *testing.T) {
	tr := sshHost(t)
	saved := maxStatusBytes
	maxStatusBytes = 16
	t.Cleanup(func() { maxStatusBytes = saved })
	sec := tr.collect("ssh.service")
	if sec.Sources["dpkg_status"].Status != hostdoc.StatusReadError {
		t.Fatalf("dpkg_status %+v", sec.Sources["dpkg_status"])
	}
	if o := entry(t, sec, "ssh.service").Program.Owners; o[0].Version != "" {
		t.Errorf("a version read from a refused file: %+v", o)
	}
}

func TestStatusWordsDecideInstalled(t *testing.T) {
	cases := map[string]bool{
		"install ok installed":        true,
		"hold ok installed":           true,
		"deinstall ok installed":      true,
		"install ok unpacked":         false,
		"install ok half-configured":  false,
		"install ok triggers-pending": false,
		"deinstall ok config-files":   false,
		"install reinstreq installed": false,
		"install ok installed extra":  false,
		"":                            false,
	}
	for status, want := range cases {
		if got := installedStatus(status); got != want {
			t.Errorf("%q: installed %v, want %v", status, got, want)
		}
	}
}

func TestMultiArchListsMatchTheirOwnStanza(t *testing.T) {
	tr := newPkgTree(t)
	tr.unitFile("app.service", "ExecStart=/usr/bin/app")
	tr.file("usr/bin/app", elfHead)
	tr.pkg("libx:arm64", "Package: libx\nStatus: install ok installed\nArchitecture: arm64\nMulti-Arch: same\nVersion: 2.0-1", "/usr/bin/app")
	tr.pkg("libx:armhf", "Package: libx\nStatus: install ok unpacked\nArchitecture: armhf\nMulti-Arch: same\nVersion: 2.0-2", "/usr/bin/app")
	o := entry(t, tr.collect("app.service"), "app.service").Program.Owners
	want := []hostdoc.Package{
		{Name: "libx", Architecture: "arm64", Installed: true, Version: "2.0-1"},
		{Name: "libx", Architecture: "armhf", Installed: false, Version: "2.0-2"},
	}
	if len(o) != 2 || o[0] != want[0] || o[1] != want[1] {
		t.Errorf("owners %+v, want %+v", o, want)
	}
}

func TestAnUnqualifiedListWithTwoStanzasIsNotGuessed(t *testing.T) {
	tr := newPkgTree(t)
	tr.unitFile("app.service", "ExecStart=/usr/bin/app")
	tr.file("usr/bin/app", elfHead)
	tr.pkg("app", "Package: app\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1", "/usr/bin/app")
	tr.status = append(tr.status, "Package: app\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2")
	tr.file("var/lib/dpkg/status", strings.Join(tr.status, "\n\n")+"\n")
	o := entry(t, tr.collect("app.service"), "app.service").Program.Owners
	if len(o) != 1 || o[0] != (hostdoc.Package{Name: "app"}) {
		t.Errorf("owners %+v", o)
	}
}

func TestSourceFieldForms(t *testing.T) {
	cases := []struct {
		value, name, version string
		malformed            bool
	}{
		{"openssh", "openssh", "", false},
		{"bash (5.2.15-2)", "bash", "5.2.15-2", false},
		{"util-linux (2.39.3-9ubuntu6.6)", "util-linux", "2.39.3-9ubuntu6.6", false},
		{"  spaced   ( 1.0 )  ", "spaced", "1.0", false},
		{"", "", "", false},
		{"foo (1.0", "foo", "", true},
		{"foo 1.0", "foo", "", true},
		{"foo ()", "foo", "", true},
	}
	for _, c := range cases {
		name, version, malformed := splitSource(c.value)
		if name != c.name || version != c.version || malformed != c.malformed {
			t.Errorf("%q: %q %q %v, want %q %q %v", c.value, name, version, malformed, c.name, c.version, c.malformed)
		}
	}
}

func TestAMalformedSourceMarksTheEntry(t *testing.T) {
	tr := sshHost(t)
	tr.status = []string{"Package: openssh-server\nStatus: install ok installed\nArchitecture: arm64\nSource: openssh (9.0\nVersion: 1:9.0p1-1"}
	tr.file("var/lib/dpkg/status", tr.status[0]+"\n")
	u := entry(t, tr.collect("ssh.service"), "ssh.service")
	if u.Finding != "record_malformed" {
		t.Errorf("finding %q", u.Finding)
	}
	if o := u.Program.Owners[0]; o.Source != "openssh" || o.SourceVersion != "" {
		t.Errorf("owner %+v", o)
	}
}

func TestAPackageFieldPastItsCapIsCut(t *testing.T) {
	tr := sshHost(t)
	long := strings.Repeat("9", hostdoc.MaxPackageFieldLen+1)
	tr.status = []string{"Package: openssh-server\nStatus: install ok installed\nArchitecture: arm64\nVersion: " + long}
	tr.file("var/lib/dpkg/status", tr.status[0]+"\n")
	u := entry(t, tr.collect("ssh.service"), "ssh.service")
	if u.Finding != "over_cap" || u.Program.Owners[0].Version != "" {
		t.Errorf("finding %q owner %+v", u.Finding, u.Program.Owners[0])
	}
}

func TestAPackageFieldAtItsCapIsKept(t *testing.T) {
	tr := sshHost(t)
	exact := strings.Repeat("9", hostdoc.MaxPackageFieldLen)
	tr.status = []string{"Package: openssh-server\nStatus: install ok installed\nArchitecture: arm64\nVersion: " + exact}
	tr.file("var/lib/dpkg/status", tr.status[0]+"\n")
	u := entry(t, tr.collect("ssh.service"), "ssh.service")
	if u.Finding != "complete" || u.Program.Owners[0].Version != exact {
		t.Errorf("finding %q owner %+v", u.Finding, u.Program.Owners[0])
	}
}

func TestAPackageFieldWithAControlByteIsMalformed(t *testing.T) {
	tr := sshHost(t)
	tr.status = []string{"Package: openssh-server\nStatus: install ok installed\nArchitecture: arm\x1b[31m64\nVersion: 1.0"}
	tr.file("var/lib/dpkg/status", tr.status[0]+"\n")
	u := entry(t, tr.collect("ssh.service"), "ssh.service")
	if u.Finding != "record_malformed" || u.Program.Owners[0].Architecture != "" {
		t.Errorf("finding %q owner %+v", u.Finding, u.Program.Owners[0])
	}
}

func TestAListNameThatIsNotAPackageNameIsMalformed(t *testing.T) {
	tr := sshHost(t)
	tr.pkg("bad name", "", "/usr/sbin/sshd")
	u := entry(t, tr.collect("ssh.service"), "ssh.service")
	if u.Finding != "record_malformed" {
		t.Errorf("finding %q", u.Finding)
	}
	if got := ownerNamesOf(u.Program); !sameStrings(got, []string{"openssh-server"}) {
		t.Errorf("owners %v", got)
	}
}

func TestMoreOwnersThanTheCapAreCut(t *testing.T) {
	tr := sshHost(t)
	tr.pkg("a-diverter", "", "/usr/sbin/sshd")
	tr.pkg("b-diverter", "", "/usr/sbin/sshd")
	u := entry(t, tr.collect("ssh.service"), "ssh.service")
	if u.Finding != "over_cap" || len(u.Program.Owners) != hostdoc.MaxOwnersPerPath {
		t.Errorf("finding %q owners %v", u.Finding, ownerNamesOf(u.Program))
	}
}

func TestTwoOwnersAreBothListed(t *testing.T) {
	tr := sshHost(t)
	tr.pkg("another", "", "/usr/sbin/sshd")
	u := entry(t, tr.collect("ssh.service"), "ssh.service")
	if u.Finding != "complete" || !sameStrings(ownerNamesOf(u.Program), []string{"another", "openssh-server"}) {
		t.Errorf("finding %q owners %v", u.Finding, ownerNamesOf(u.Program))
	}
}

func TestAnEarlierFindingIsNotReplacedByACut(t *testing.T) {
	tr := sshHost(t)
	tr.file("usr/lib/systemd/system/ssh.service", "[Service]\nExecStart=-/usr/sbin/sshd\n")
	tr.pkg("a", "", "/lib/systemd/system/ssh.service")
	tr.pkg("b", "", "/lib/systemd/system/ssh.service")
	if u := entry(t, tr.collect("ssh.service"), "ssh.service"); u.Finding != "exec_start_prefixed" {
		t.Errorf("finding %q", u.Finding)
	}
}

// ------------------------------------------------------------ the unit list

func TestUnitsPastTheCapAreCutAndSaySo(t *testing.T) {
	tr := sshHost(t)
	var units []string
	for i := 0; i < hostdoc.MaxPackageUnits+5; i++ {
		units = append(units, fmt.Sprintf("u%04d.service", i))
	}
	sec := tr.collect(units...)
	if !sec.UnitsCut || len(sec.Units) != hostdoc.MaxPackageUnits {
		t.Fatalf("cut %v, %d units", sec.UnitsCut, len(sec.Units))
	}
	if sec.Units[0].Unit != "u0000.service" || sec.Units[len(sec.Units)-1].Unit != units[hostdoc.MaxPackageUnits-1] {
		t.Errorf("kept %s to %s, want the first by name", sec.Units[0].Unit, sec.Units[len(sec.Units)-1].Unit)
	}
}

func TestUnitsAtTheCapAreNotCut(t *testing.T) {
	var units []string
	for i := 0; i < hostdoc.MaxPackageUnits; i++ {
		units = append(units, fmt.Sprintf("u%d.service", i))
	}
	sec := sshHost(t).collect(units...)
	if sec.UnitsCut || len(sec.Units) != hostdoc.MaxPackageUnits {
		t.Errorf("cut %v, %d units", sec.UnitsCut, len(sec.Units))
	}
}

func TestNamesThatAreNotServiceUnitsAreDropped(t *testing.T) {
	sec := sshHost(t).collect("ssh.service", "ssh.service", "ssh.socket", "init.scope", "../../etc/passwd.service", "", "a b.service", strings.Repeat("a", 250)+".service")
	if len(sec.Units) != 1 || sec.Units[0].Unit != "ssh.service" {
		t.Errorf("units %+v", sec.Units)
	}
}

func TestNoUnitsReadsNoFileListAndNoStatus(t *testing.T) {
	tr := sshHost(t)
	tr.file("var/lib/dpkg/status", "garbage that would not parse\x00")
	sec := tr.collect()
	if sec.Status != hostdoc.StatusCollected || len(sec.Units) != 0 {
		t.Errorf("status %q units %+v", sec.Status, sec.Units)
	}
}

func TestTwoRunsAreByteIdentical(t *testing.T) {
	tr := sshHost(t)
	tr.pkg("another", "", "/usr/sbin/sshd")
	tr.unitFile("nginx.service", "ExecStart=/usr/sbin/nginx")
	a := mustMarshal(t, tr.collect("ssh.service", "nginx.service", "gone.service"))
	b := mustMarshal(t, tr.collect("gone.service", "nginx.service", "ssh.service"))
	if string(a) != string(b) {
		t.Errorf("two runs differ:\n%s\n%s", a, b)
	}
}

func TestListeningServiceUnits(t *testing.T) {
	sockets := &hostdoc.SocketsSection{Listening: []hostdoc.ListeningSocket{
		{Cgroup: "/system.slice/nginx.service", Unit: "nginx.service"},
		{Cgroup: "/system.slice/nginx.service", Unit: "nginx.service"},
		{Cgroup: "/system.slice/system-postgresql.slice/postgresql@15-main.service", Unit: "postgresql@15-main.service"},
		{Cgroup: "/custom.slice/app.service", Unit: "app.service"},
		{Cgroup: "/sshd.service", Unit: "sshd.service"},
		// a user's own service, under the user manager
		{Cgroup: "/user.slice/user-1000.slice/user@1000.service/app.slice/web.service", Unit: "web.service"},
		// a container running its own systemd
		{Cgroup: "/system.slice/docker-0123abcd.scope/system.slice/nginx2.service", Unit: "nginx2.service"},
		{Cgroup: "/machine.slice/machine-c1.scope/payload/system.slice/db.service", Unit: "db.service"},
		{Cgroup: "/init.scope", Unit: "init.scope"},
		{Cgroup: "/user.slice/user-1000.slice/session-3.scope", Unit: "session-3.scope"},
		{Cgroup: "/system.slice/docker.service", Unit: "docker.service"},
		// two socket units that hold their sockets themselves
		{Cgroup: "/system.slice/ssh.socket", Unit: "ssh.socket", Protocol: "tcp", Port: 22},
		{Cgroup: "/system.slice/system-inst.slice/inst@7006.socket", Unit: "inst@7006.socket", Protocol: "tcp", Port: 7006},
		{},
	}}
	units := &hostdoc.SocketUnitsSection{Units: []hostdoc.SocketUnit{
		{Name: "ssh.socket", Parsed: true, ServiceUnit: "ssh.service", Listen: []hostdoc.SocketUnitListen{{Kind: "port_only", Port: 22}}},
		{Name: "journald.socket", Parsed: true, ServiceUnit: "journald.service", Listen: []hostdoc.SocketUnitListen{{Kind: "path", Value: "/run/x"}}},
		{Name: "t@.socket", Parsed: true, Template: true, ServiceUnit: "t@.service", Listen: []hostdoc.SocketUnitListen{{Kind: "port_only", Port: 1}}},
		{Name: "inst@7006.socket", Parsed: true, Instance: "7006", ServiceUnit: "inst@7006.service", Listen: []hostdoc.SocketUnitListen{{Kind: "port_only", Port: 7006}}},
		{Name: "masked.socket", Masked: true},
		{Name: "alias.socket", AliasOf: "ssh.socket"},
		{Name: "broken.socket", Parsed: false, ServiceUnit: "broken.service"},
		{Name: "unknown.socket", Parsed: true, ServiceUnit: "", Listen: []hostdoc.SocketUnitListen{{Kind: "port_only", Port: 2}}},
	}}
	got := ListeningServiceUnits(sockets, units)
	want := []string{"app.service", "docker.service", "inst@7006.service", "nginx.service",
		"postgresql@15-main.service", "ssh.service", "sshd.service"}
	if !sameStrings(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
	if got := ListeningServiceUnits(nil, nil); len(got) != 0 {
		t.Errorf("nothing in, %v out", got)
	}
}

// A socket unit names a service for this section only while that socket unit
// holds a listening socket. Measured on 2026-10-03 with OpenSSH's ssh.socket
// enabled and ssh.service inactive, on Debian 12 (systemd 252), Debian 13
// (systemd 257) and Ubuntu 24.04 (systemd 255): the kernel reports the
// listening socket in the socket unit's own cgroup, "/system.slice/ssh.socket".

var sshSocketUnit = hostdoc.SocketUnit{Name: "ssh.socket", Parsed: true, ServiceUnit: "ssh.service",
	Listen: []hostdoc.SocketUnitListen{{Kind: "port_only", Port: 22}}}

func TestASocketUnitOnDiskWithNothingListeningNamesNoService(t *testing.T) {
	// OpenSSH installed and not started, as measured on a clean Debian 12:
	// its package ships ssh.socket, which declares port 22, and nothing
	// listens. Until this test the section still held ssh.service.
	sockets := &hostdoc.SocketsSection{}
	units := &hostdoc.SocketUnitsSection{Units: []hostdoc.SocketUnit{sshSocketUnit}}
	if got := ListeningServiceUnits(sockets, units); len(got) != 0 {
		t.Errorf("nothing listens and the section names %v", got)
	}
	if got := ListeningServiceUnits(nil, units); len(got) != 0 {
		t.Errorf("no socket table and the section names %v", got)
	}
}

func TestASocketUnitThatHoldsAListeningSocketNamesItsService(t *testing.T) {
	sockets := &hostdoc.SocketsSection{Listening: []hostdoc.ListeningSocket{
		{Protocol: "tcp", Family: "v4", Port: 22, Cgroup: "/system.slice/ssh.socket", Unit: "ssh.socket"},
		{Protocol: "tcp", Family: "v6", Port: 22, Cgroup: "/system.slice/ssh.socket", Unit: "ssh.socket"},
	}}
	units := &hostdoc.SocketUnitsSection{Units: []hostdoc.SocketUnit{sshSocketUnit}}
	if got := ListeningServiceUnits(sockets, units); !sameStrings(got, []string{"ssh.service"}) {
		t.Errorf("got %v, want ssh.service", got)
	}
}

func TestASocketUnitWithTwoPortsAndOneListeningNamesItsService(t *testing.T) {
	// One listening socket is enough: the service is behind a listening
	// socket, which is all this section asks.
	two := hostdoc.SocketUnit{Name: "two.socket", Parsed: true, ServiceUnit: "two.service",
		Listen: []hostdoc.SocketUnitListen{{Kind: "port_only", Port: 7001}, {Kind: "port_only", Port: 7002}}}
	sockets := &hostdoc.SocketsSection{Listening: []hostdoc.ListeningSocket{
		{Protocol: "tcp", Family: "v4", Port: 7002, Cgroup: "/system.slice/two.socket", Unit: "two.socket"},
	}}
	units := &hostdoc.SocketUnitsSection{Units: []hostdoc.SocketUnit{two}}
	if got := ListeningServiceUnits(sockets, units); !sameStrings(got, []string{"two.service"}) {
		t.Errorf("got %v, want two.service", got)
	}
}

func TestAPortASocketUnitDeclaresThatAnotherServiceListensOnNamesOnlyThatService(t *testing.T) {
	// ssh.socket is on disk and not enabled, and another server listens on
	// port 22 as a service of its own. The listener is that service's, so
	// that service is named and ssh.service is not: the port being the same
	// says nothing about whose socket it is.
	sockets := &hostdoc.SocketsSection{Listening: []hostdoc.ListeningSocket{
		{Protocol: "tcp", Family: "v4", Port: 22, Cgroup: "/system.slice/dropbear.service", Unit: "dropbear.service"},
	}}
	units := &hostdoc.SocketUnitsSection{Units: []hostdoc.SocketUnit{sshSocketUnit}}
	if got := ListeningServiceUnits(sockets, units); !sameStrings(got, []string{"dropbear.service"}) {
		t.Errorf("got %v, want dropbear.service alone", got)
	}
}

func TestASocketUnitOutsideTheHostsOwnSlicesNamesNoService(t *testing.T) {
	// The same rule a service's own socket follows: a socket unit under a
	// user's manager or inside a container is not the host's unit of that
	// name, whatever unit file the host has.
	sockets := &hostdoc.SocketsSection{Listening: []hostdoc.ListeningSocket{
		{Protocol: "tcp", Port: 22, Cgroup: "/user.slice/user-1000.slice/user@1000.service/app.slice/ssh.socket", Unit: "ssh.socket"},
		{Protocol: "tcp", Port: 22, Cgroup: "/system.slice/docker-0123abcd.scope/system.slice/ssh.socket", Unit: "ssh.socket"},
		{Protocol: "tcp", Port: 22, Cgroup: "/init.scope", Unit: "init.scope"},
		{Protocol: "tcp", Port: 22, Cgroup: "/system.slice/other.socket", Unit: "other.socket"},
	}}
	units := &hostdoc.SocketUnitsSection{Units: []hostdoc.SocketUnit{sshSocketUnit}}
	if got := ListeningServiceUnits(sockets, units); len(got) != 0 {
		t.Errorf("no socket of the host's ssh.socket listens and the section names %v", got)
	}
}

func TestAMaskedTemplateOrUnreadSocketUnitNamesNoServiceEvenWhenItsNameListens(t *testing.T) {
	sockets := &hostdoc.SocketsSection{Listening: []hostdoc.ListeningSocket{
		{Protocol: "tcp", Port: 1, Cgroup: "/system.slice/masked.socket", Unit: "masked.socket"},
		{Protocol: "tcp", Port: 2, Cgroup: "/system.slice/broken.socket", Unit: "broken.socket"},
		{Protocol: "tcp", Port: 3, Cgroup: "/system.slice/path.socket", Unit: "path.socket"},
	}}
	units := &hostdoc.SocketUnitsSection{Units: []hostdoc.SocketUnit{
		{Name: "masked.socket", Masked: true, ServiceUnit: "masked.service"},
		{Name: "broken.socket", Parsed: false, ServiceUnit: "broken.service"},
		{Name: "path.socket", Parsed: true, ServiceUnit: "path.service", Listen: []hostdoc.SocketUnitListen{{Kind: "path", Value: "/run/x"}}},
	}}
	if got := ListeningServiceUnits(sockets, units); len(got) != 0 {
		t.Errorf("got %v, want none", got)
	}
}

// ------------------------------------------------------------- os-release

func TestDistributionReading(t *testing.T) {
	cases := map[string]struct {
		etc, lib string
		want     *hostdoc.Distribution
		status   hostdoc.SectionStatus
	}{
		"only the vendor file": {"", "ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\n",
			&hostdoc.Distribution{ID: "ubuntu", VersionID: "24.04", VersionCodename: "noble"}, hostdoc.StatusCollected},
		"the /etc file wins and the two are never mixed": {"ID=debian\n", "ID=ubuntu\nVERSION_ID=24.04\n",
			&hostdoc.Distribution{ID: "debian"}, hostdoc.StatusCollected},
		"single quotes": {"ID='debian'\nVERSION_ID='13'\n", "",
			&hostdoc.Distribution{ID: "debian", VersionID: "13"}, hostdoc.StatusCollected},
		"the last of a repeated key": {"ID=first\nID=debian\n", "",
			&hostdoc.Distribution{ID: "debian"}, hostdoc.StatusCollected},
		"values outside the character set are left out": {"ID=\"Debian GNU\"\nVERSION_ID=12\nVERSION_CODENAME=Bookworm\n", "",
			&hostdoc.Distribution{VersionID: "12"}, hostdoc.StatusCollected},
		"a value past its cap is left out": {"ID=" + strings.Repeat("a", hostdoc.MaxDistributionFieldLen+1) + "\n", "",
			&hostdoc.Distribution{}, hostdoc.StatusCollected},
		"neither file": {"", "", nil, hostdoc.StatusNotPresent},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tr := newPkgTree(t)
			tr.remove("etc/os-release")
			tr.remove("usr/lib/os-release")
			if c.etc != "" {
				tr.file("etc/os-release", c.etc)
			}
			if c.lib != "" {
				tr.file("usr/lib/os-release", c.lib)
			}
			sec := tr.collect()
			if sec.Sources["os_release"].Status != c.status {
				t.Errorf("os_release %+v", sec.Sources["os_release"])
			}
			if (sec.Distribution == nil) != (c.want == nil) || (c.want != nil && *sec.Distribution != *c.want) {
				t.Errorf("distribution %+v, want %+v", sec.Distribution, c.want)
			}
		})
	}
}

func TestAnUnreadableEtcOsReleaseIsNotReplacedByTheVendorFile(t *testing.T) {
	skipIfRoot(t)
	tr := newPkgTree(t)
	tr.remove("etc/os-release")
	tr.file("etc/os-release", "ID=debian\n")
	tr.deny("etc/os-release")
	sec := tr.collect()
	if sec.Distribution != nil || sec.Sources["os_release"].Status != hostdoc.StatusPermissionDenied {
		t.Errorf("distribution %+v os_release %+v", sec.Distribution, sec.Sources["os_release"])
	}
}

// ---------------------------------------------------------- the whole run

func TestTheSectionIsWhatAReaderExpects(t *testing.T) {
	b := mustMarshal(t, sshHost(t).collect("ssh.service"))
	var doc struct {
		Packages struct {
			Status  string `json:"status"`
			Sources map[string]struct {
				Status string `json:"status"`
			} `json:"sources"`
			Units []map[string]any `json:"units"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Packages.Status != "collected" || len(doc.Packages.Units) != 1 {
		t.Fatalf("%s", b)
	}
	for _, key := range []string{"unit", "finding", "unit_file", "program", "program_kind"} {
		if _, ok := doc.Packages.Units[0][key]; !ok {
			t.Errorf("the entry has no %q: %s", key, b)
		}
	}
}
