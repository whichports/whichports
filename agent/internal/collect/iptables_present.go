package collect

// Which legacy tables the kernel already holds, decided before the agent asks
// the kernel about any of them. Portable and free of syscalls, so the decision
// is tested on any platform.
//
// Why the order matters. Asking the kernel for a table it does not hold
// creates the table. The info call the read starts with looks the table up
// with xt_request_find_table_lock, which loads the module iptable_<name> or
// ip6table_<name> when the table is missing, and xt_find_table_lock then
// builds the table, empty and with every chain at ACCEPT, in the asking
// process's network namespace from the template the module registered
// (net/netfilter/x_tables.c and net/ipv4/netfilter/ip_tables.c, get_info,
// read at the v6.8, v6.12 and v7.0 tags on 2026-10-27). A server with no
// legacy tables was left with five after one collection, and the nat table's
// module pulls in connection tracking. The agent is read only (SI-3), so it
// never asks about a table the kernel does not already list.
//
// The list is /proc/net/ip_tables_names, and /proc/net/ip6_tables_names for
// IPv6: the tables of the reader's network namespace, one name a line. Reading
// it walks that list and changes nothing (xt_table_seq_start and
// xt_table_seq_show in x_tables.c). It exists only while ip_tables, or
// ip6_tables, is in the kernel, because the module's own namespace setup makes
// it (ip_tables_net_init calls xt_proto_init). It is what iptables-legacy-save
// itself reads to choose the tables it dumps, and a missing file means no
// tables to it (for_each_table in iptables/iptables-save.c, iptables 1.8.11,
// read from Debian's source package on 2026-10-27).
//
// The file is mode 0440 and owned by root (xt_proto_init), so the agent's own
// user cannot read it. Then the one file left that is readable by anyone and
// says anything is /proc/modules, the loaded modules. When ip_tables is in it,
// ip_tables is a loadable module, so no table module can be built into the
// kernel (a table module calls into ip_tables, and code built into the kernel
// cannot call into a loadable module). A table whose module is not loaded then
// exists in no namespace at all. A table whose module is loaded may exist here
// or only in another namespace, and asking would create it where it is
// missing, so that table is a refused read and the agent does not ask.
//
// One window stays open, and it is the time between two system calls: a table
// the list held a moment before can vanish only if an administrator unloads
// its module in between, and then the info call would load it again.

import (
	"bytes"
	"errors"
	"io/fs"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

// modulesFile lists the loaded modules. Readable by any user.
const modulesFile = "/proc/modules"

// legacyPlan is what the collector may do for one family's five tables.
type legacyPlan struct {
	// ask holds the tables the kernel already lists, in legacyTables order.
	// They are the only tables the getsockopt read may name.
	ask []string
	// decided holds the verdict of every other table, reached with no call.
	decided map[string]hostdoc.Section
}

// planLegacyRead decides from the two files' contents and the errors their
// reads returned. modules is read only when names could not be.
func planLegacyRead(fam legacyFamily, names []byte, namesErr error, modules []byte, modulesErr error) legacyPlan {
	switch {
	case namesErr == nil:
		listed, ok := parseTableNames(names)
		if !ok {
			return decideAll(hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed})
		}
		plan := legacyPlan{decided: map[string]hostdoc.Section{}}
		for _, table := range legacyTables {
			if listed[table] {
				plan.ask = append(plan.ask, table)
			} else {
				plan.decided[table] = hostdoc.Section{Status: hostdoc.StatusNotPresent}
			}
		}
		return plan
	case errors.Is(namesErr, fs.ErrNotExist):
		// ip_tables is not in the kernel, so it holds no legacy table.
		return decideAll(hostdoc.Section{Status: hostdoc.StatusNotPresent})
	case errors.Is(namesErr, fs.ErrPermission):
		return planFromModules(fam, modules, modulesErr)
	default:
		return decideAll(hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed})
	}
}

// planFromModules decides when the list could not be read. It never asks.
func planFromModules(fam legacyFamily, modules []byte, modulesErr error) legacyPlan {
	refused := hostdoc.Section{Status: hostdoc.StatusPermissionDenied, Cause: hostdoc.CausePermission}
	if modulesErr != nil {
		return decideAll(refused)
	}
	loaded := parseModuleNames(modules)
	if !loaded[fam.coreModule] {
		// ip_tables is built into the kernel, so a table may be too.
		return decideAll(refused)
	}
	plan := legacyPlan{decided: map[string]hostdoc.Section{}}
	for _, table := range legacyTables {
		if loaded[fam.tableModule+table] {
			plan.decided[table] = refused
		} else {
			plan.decided[table] = hostdoc.Section{Status: hostdoc.StatusNotPresent}
		}
	}
	return plan
}

func decideAll(verdict hostdoc.Section) legacyPlan {
	plan := legacyPlan{decided: map[string]hostdoc.Section{}}
	for _, table := range legacyTables {
		plan.decided[table] = verdict
	}
	return plan
}

// parseTableNames reads the kernel's list: each line one table name and a
// newline, as xt_table_seq_show prints it. A line that is not a name the
// kernel could print makes the whole list unreadable, the way iptables-save
// refuses a badly formed one, rather than a list with a table missing.
func parseTableNames(content []byte) (map[string]bool, bool) {
	listed := map[string]bool{}
	if len(content) == 0 {
		return listed, true
	}
	if content[len(content)-1] != '\n' {
		return nil, false
	}
	for _, line := range bytes.Split(content[:len(content)-1], []byte("\n")) {
		if len(line) == 0 || len(line) >= xtTableNameLen {
			return nil, false
		}
		for _, c := range line {
			if c <= ' ' || c > '~' {
				return nil, false
			}
		}
		listed[string(line)] = true
	}
	return listed, true
}

// parseModuleNames takes the first word of each /proc/modules line, the
// module's name. Nothing else on the line is used.
func parseModuleNames(content []byte) map[string]bool {
	loaded := map[string]bool{}
	for _, line := range bytes.Split(content, []byte("\n")) {
		fields := bytes.Fields(line)
		if len(fields) > 0 {
			loaded[string(fields[0])] = true
		}
	}
	return loaded
}
