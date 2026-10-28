//go:build linux

// The syscall half of the legacy iptables collector: a raw socket as a
// getsockopt handle (nothing is ever sent or received on it, SI-1) and the
// two-call read the iptables-legacy binary itself performs, for the tables
// the kernel already lists and no other (iptables_present.go). Parsing lives
// in iptables_parse.go, portable and fuzzable.
package collect

import (
	"encoding/binary"
	"errors"
	"io/fs"
	"sort"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/whichports/whichports/agent/internal/hostdoc"
)

const (
	xtSoGetInfo     = 64 // IPT_BASE_CTL and IP6T_BASE_CTL
	xtSoGetEntries  = 65
	xtGetInfoLen    = 84 // struct ipt_getinfo and ip6t_getinfo
	xtEntriesHdrLen = 40 // struct ipt_get_entries header, padded for align 8

	// legacyMaxRuleset caps how much ruleset is fetched, the same runaway
	// guard every other collector applies.
	legacyMaxRuleset = 32 << 20
)

var (
	v4Family = withSocket(v4Parse, unix.AF_INET, unix.SOL_IP)
	v6Family = withSocket(v6Parse, unix.AF_INET6, unix.SOL_IPV6)
)

func withSocket(f legacyFamily, af, level int) legacyFamily {
	f.af, f.level = af, level
	return f
}

// CollectIptablesLive and CollectIp6tablesLive read the live kernel. Each is
// the only impure part of its collector; parsing is a pure function of the
// bytes the kernel returned.
func CollectIptablesLive() *hostdoc.IptablesSection  { return collectLegacyLive(v4Family) }
func CollectIp6tablesLive() *hostdoc.IptablesSection { return collectLegacyLive(v6Family) }

func collectLegacyLive(fam legacyFamily) *hostdoc.IptablesSection {
	sec := &hostdoc.IptablesSection{Sources: map[string]hostdoc.Section{}}

	// First the kernel's own list of the tables it holds, and only then a
	// call naming one of them. Asking about a table the kernel does not hold
	// makes it create one (iptables_present.go), so a table missing from the
	// list is never named in a call.
	names, namesErr := readCapped(fam.namesFile)
	var modules []byte
	var modulesErr error
	if errors.Is(namesErr, fs.ErrPermission) {
		modules, modulesErr = readCapped(modulesFile)
	}
	plan := planLegacyRead(fam, names, namesErr, modules, modulesErr)
	for table, verdict := range plan.decided {
		sec.Sources[table] = verdict
	}
	if len(plan.ask) == 0 {
		// No socket either: nothing is left to ask.
		sec.Section = aggregateSources(sec.Sources)
		return sec
	}

	fd, err := unix.Socket(fam.af, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		verdict := hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseSocketError}
		switch err {
		case unix.EPERM, unix.EACCES:
			// Without CAP_NET_RAW there is no handle to ask through.
			verdict = hostdoc.Section{Status: hostdoc.StatusPermissionDenied, Cause: hostdoc.CausePermission}
		case unix.EAFNOSUPPORT:
			// The address family does not exist on this kernel, the normal
			// state for ip6tables on an ipv6.disable=1 host. Measured
			// absence, not an error.
			verdict = hostdoc.Section{Status: hostdoc.StatusNotPresent}
		}
		for _, tb := range plan.ask {
			sec.Sources[tb] = verdict
		}
		sec.Section = aggregateSources(sec.Sources)
		return sec
	}
	defer unix.Close(fd)

	for _, tableName := range plan.ask {
		blob, info, err := legacyReadTable(fd, fam.level, tableName)
		if err != nil {
			sec.Sources[tableName] = legacyErrnoVerdict(err)
			continue
		}
		table, perr := parseLegacyTable(fam, tableName, info, blob)
		if perr != nil {
			sec.Sources[tableName] = hostdoc.Section{
				Status: hostdoc.StatusReadError, Cause: hostdoc.CauseParseFailed,
			}
			continue
		}
		sec.Sources[tableName] = hostdoc.Section{Status: hostdoc.StatusCollected}
		sec.Tables = append(sec.Tables, table)
	}

	sort.Slice(sec.Tables, func(i, j int) bool { return sec.Tables[i].Name < sec.Tables[j].Name })
	sec.Section = aggregateSources(sec.Sources)
	return sec
}

// legacyReadTable performs the info + entries pair. The kernel answers the
// entries call with EAGAIN when the ruleset changed size between the two
// calls (net/ipv4/netfilter/ip_tables.c, get_entries, checked at v6.8), so
// the pair retries a few times before giving up: a busy fail2ban can be
// editing rules at any moment.
func legacyReadTable(fd, level int, table string) ([]byte, legacyInfo, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		info, err := legacyGetInfo(fd, level, table)
		if err != nil {
			return nil, legacyInfo{}, err
		}
		blob, err := legacyGetEntries(fd, level, table, info.size)
		if err == unix.EAGAIN {
			lastErr = err
			continue
		}
		if err != nil {
			return nil, legacyInfo{}, err
		}
		return blob, info, nil
	}
	return nil, legacyInfo{}, lastErr
}

// legacyErrnoVerdict types a getsockopt failure. ENOPROTOOPT means the
// x_tables module is not loaded and ENOENT means this table does not exist;
// both are the absence of the subsystem, not an error. Only a table the
// kernel listed is asked about, so either one now means it went away in
// between.
func legacyErrnoVerdict(err error) hostdoc.Section {
	switch err {
	case unix.ENOPROTOOPT, unix.ENOENT:
		return hostdoc.Section{Status: hostdoc.StatusNotPresent}
	case unix.EPERM, unix.EACCES:
		return hostdoc.Section{Status: hostdoc.StatusPermissionDenied, Cause: hostdoc.CausePermission}
	}
	return hostdoc.Section{Status: hostdoc.StatusReadError, Cause: hostdoc.CauseSocketError}
}

// getsockoptRaw performs a getsockopt with an in/out buffer, which the
// x_tables interface requires: the table name goes in, the kernel fills the
// rest of the same buffer. Neither the stdlib nor x/sys wraps this shape.
func getsockoptRaw(fd, level, opt int, buf []byte) error {
	optlen := uint32(len(buf))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(opt),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&optlen)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func legacyGetInfo(fd, level int, table string) (legacyInfo, error) {
	buf := make([]byte, xtGetInfoLen)
	copy(buf[:xtTableNameLen-1], table)
	if err := getsockoptRaw(fd, level, xtSoGetInfo, buf); err != nil {
		return legacyInfo{}, err
	}
	le := binary.LittleEndian
	info := legacyInfo{
		validHooks: le.Uint32(buf[32:]),
		numEntries: le.Uint32(buf[76:]),
		size:       le.Uint32(buf[80:]),
	}
	for i := 0; i < numHooks; i++ {
		info.hookEntry[i] = le.Uint32(buf[36+4*i:])
		info.underflow[i] = le.Uint32(buf[56+4*i:])
	}
	return info, nil
}

func legacyGetEntries(fd, level int, table string, size uint32) ([]byte, error) {
	if size > legacyMaxRuleset {
		return nil, unix.E2BIG
	}
	buf := make([]byte, xtEntriesHdrLen+int(size))
	copy(buf[:xtTableNameLen-1], table)
	binary.LittleEndian.PutUint32(buf[xtTableNameLen:], size)
	if err := getsockoptRaw(fd, level, xtSoGetEntries, buf); err != nil {
		return nil, err
	}
	return buf[xtEntriesHdrLen:], nil
}
