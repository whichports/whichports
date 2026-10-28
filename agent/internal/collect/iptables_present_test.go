package collect

// The decision taken before the legacy read asks the kernel anything. The
// kernel creates a legacy table, and loads its module, when it is asked about
// one it does not hold, so these tests hold the agent to asking only about
// tables the kernel already lists, and to deciding every other table without
// a call. They are portable, because the decision is a pure function of the
// two files' bytes and the errors their reads returned.

import (
	"errors"
	"io/fs"
	"reflect"
	"syscall"
	"testing"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

var (
	notPresent = hostdoc.Section{Status: hostdoc.StatusNotPresent}
	denied     = hostdoc.Section{Status: hostdoc.StatusPermissionDenied, Cause: hostdoc.CausePermission}
	unreadable = hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed}
)

// modulesLine is one /proc/modules line in the kernel's own layout, as an
// unprivileged reader sees it, with the address shown as zero.
func modulesLine(name string) string {
	return name + " 32768 0 - Live 0x0000000000000000\n"
}

// everyTable gives each of the five tables the same verdict.
func everyTable(verdict hostdoc.Section) map[string]hostdoc.Section {
	out := map[string]hostdoc.Section{}
	for _, table := range legacyTables {
		out[table] = verdict
	}
	return out
}

func checkPlan(t *testing.T, got legacyPlan, wantAsk []string, wantDecided map[string]hostdoc.Section) {
	t.Helper()
	if len(got.ask) != 0 || len(wantAsk) != 0 {
		if !reflect.DeepEqual(got.ask, wantAsk) {
			t.Errorf("tables asked about = %v, want %v", got.ask, wantAsk)
		}
	}
	if !reflect.DeepEqual(got.decided, wantDecided) {
		t.Errorf("decided without a call = %v, want %v", got.decided, wantDecided)
	}
	for _, table := range got.ask {
		if _, both := got.decided[table]; both {
			t.Errorf("table %q is both asked about and decided", table)
		}
	}
}

// The state of the server in the big test before the agent ran: ip_tables
// loaded, so the file exists, and no table in it. Asking about any of the
// five here is what created them.
func TestAnEmptyTableListAsksTheKernelNothing(t *testing.T) {
	plan := planLegacyRead(v4Parse, []byte(""), nil, nil, nil)
	checkPlan(t, plan, nil, everyTable(notPresent))
}

func TestNoTableListMeansNoLegacyTablesAndNoCall(t *testing.T) {
	missing := &fs.PathError{Op: "open", Path: v4Parse.namesFile, Err: syscall.ENOENT}
	plan := planLegacyRead(v4Parse, nil, missing, nil, nil)
	checkPlan(t, plan, nil, everyTable(notPresent))
}

func TestOnlyTheListedTablesAreAskedAbout(t *testing.T) {
	plan := planLegacyRead(v4Parse, []byte("nat\nfilter\n"), nil, nil, nil)
	checkPlan(t, plan, []string{"filter", "nat"}, map[string]hostdoc.Section{
		"mangle": notPresent, "raw": notPresent, "security": notPresent,
	})
}

func TestAllFiveListedAreAllAskedAbout(t *testing.T) {
	plan := planLegacyRead(v4Parse, []byte("security\nraw\nmangle\nnat\nfilter\n"), nil, nil, nil)
	checkPlan(t, plan, legacyTables, map[string]hostdoc.Section{})
}

// A name the agent has no reader for is not asked about. The five are every
// table the IPv4 and IPv6 x_tables modules register.
func TestAnUnknownListedNameIsNotAskedAbout(t *testing.T) {
	plan := planLegacyRead(v4Parse, []byte("broute\nfilter\n"), nil, nil, nil)
	checkPlan(t, plan, []string{"filter"}, map[string]hostdoc.Section{
		"nat": notPresent, "mangle": notPresent, "raw": notPresent, "security": notPresent,
	})
}

// A list the agent cannot make out is not read as "no tables", and it is not
// a reason to go and ask the kernel either.
func TestAMalformedTableListAsksNothingAndSaysSo(t *testing.T) {
	for name, content := range map[string]string{
		"no final newline":       "filter",
		"an empty line":          "filter\n\nnat\n",
		"a name past the limit":  "abcdefghijklmnopqrstuvwxyz0123456\n",
		"a control byte":         "fil\x00ter\n",
		"a space inside a name":  "fil ter\n",
		"a line of spaces alone": " \n",
	} {
		t.Run(name, func(t *testing.T) {
			plan := planLegacyRead(v4Parse, []byte(content), nil, nil, nil)
			checkPlan(t, plan, nil, everyTable(unreadable))
		})
	}
}

func TestAnOtherReadErrorAsksNothingAndSaysSo(t *testing.T) {
	broken := &fs.PathError{Op: "read", Path: v4Parse.namesFile, Err: syscall.EIO}
	plan := planLegacyRead(v4Parse, nil, broken, []byte(modulesLine("ip_tables")), nil)
	checkPlan(t, plan, nil, everyTable(unreadable))
}

// The file is 0440 and owned by root, so the agent's own user cannot read it.
// The module list is readable by anyone. When ip_tables is a loadable module,
// no table module can be built into the kernel, so a table whose module is not
// loaded does not exist anywhere.
func TestADeniedListWithNoTableModuleLoadedReadsNotPresent(t *testing.T) {
	plan := planLegacyRead(v4Parse, nil, permissionError(v4Parse.namesFile),
		[]byte(modulesLine("nf_tables")+modulesLine("ip_tables")+modulesLine("x_tables")), nil)
	checkPlan(t, plan, nil, everyTable(notPresent))
}

// A loaded table module says the table may exist, in this namespace or in
// another. The agent cannot tell which without the list, and asking the kernel
// would create it where it is missing, so it says the read was refused.
func TestADeniedListWithATableModuleLoadedIsRefusedForThatTable(t *testing.T) {
	plan := planLegacyRead(v4Parse, nil, permissionError(v4Parse.namesFile),
		[]byte(modulesLine("iptable_nat")+modulesLine("iptable_filter")+modulesLine("ip_tables")), nil)
	checkPlan(t, plan, nil, map[string]hostdoc.Section{
		"filter": denied, "nat": denied,
		"mangle": notPresent, "raw": notPresent, "security": notPresent,
	})
}

// ip_tables built into the kernel never shows in the module list, and then a
// table may be built in too. Nothing can be said about any of them.
func TestADeniedListWithIpTablesBuiltInIsRefusedForEveryTable(t *testing.T) {
	plan := planLegacyRead(v4Parse, nil, permissionError(v4Parse.namesFile),
		[]byte(modulesLine("nf_tables")), nil)
	checkPlan(t, plan, nil, everyTable(denied))
}

func TestADeniedListAndAnUnreadableModuleListIsRefused(t *testing.T) {
	plan := planLegacyRead(v4Parse, nil, permissionError(v4Parse.namesFile),
		nil, permissionError("/proc/modules"))
	checkPlan(t, plan, nil, everyTable(denied))
}

// Only a whole module name counts. iptable_filterx is not iptable_filter.
func TestAModuleNameMustMatchWhole(t *testing.T) {
	plan := planLegacyRead(v4Parse, nil, permissionError(v4Parse.namesFile),
		[]byte(modulesLine("ip_tables")+modulesLine("iptable_filterx")+modulesLine("xiptable_nat")), nil)
	checkPlan(t, plan, nil, everyTable(notPresent))
}

// The IPv6 tables have their own list file and their own modules. An IPv4
// table module says nothing about IPv6.
func TestTheIPv6FamilyReadsItsOwnFileAndModules(t *testing.T) {
	if v6Parse.namesFile != "/proc/net/ip6_tables_names" || v4Parse.namesFile != "/proc/net/ip_tables_names" {
		t.Fatalf("list files = %q and %q", v4Parse.namesFile, v6Parse.namesFile)
	}
	modules := []byte(modulesLine("iptable_filter") + modulesLine("ip_tables") + modulesLine("ip6_tables"))
	plan := planLegacyRead(v6Parse, nil, permissionError(v6Parse.namesFile), modules, nil)
	checkPlan(t, plan, nil, everyTable(notPresent))

	modules = []byte(modulesLine("ip6table_raw") + modulesLine("ip6_tables"))
	plan = planLegacyRead(v6Parse, nil, permissionError(v6Parse.namesFile), modules, nil)
	checkPlan(t, plan, nil, map[string]hostdoc.Section{
		"raw": denied, "filter": notPresent, "nat": notPresent, "mangle": notPresent, "security": notPresent,
	})
}

func permissionError(path string) error {
	return &fs.PathError{Op: "open", Path: path, Err: syscall.EACCES}
}

// The test helpers above build their errors the way os.ReadFile returns them,
// so the plan has to see through the wrapping.
func TestTheErrorsAreSeenThroughTheirWrapping(t *testing.T) {
	if !errors.Is(permissionError("x"), fs.ErrPermission) {
		t.Fatal("EACCES in a PathError is not fs.ErrPermission")
	}
}
