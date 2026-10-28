// The nftables rule-comment TLV parser, portable on purpose so the fuzzer
// exercises it everywhere: it eats bytes an admin (or anything that can add
// a rule) controls.
package collect

// ruleComment extracts the rule author's comment from the rule's userdata,
// which is a sequence of type-length-value entries; type 0 is the comment,
// NUL-terminated (libnftnl's NFTNL_UDATA_RULE_COMMENT). Best effort: any
// malformed TLV yields no comment, never an error, because the comment is
// decoration on evidence, not evidence.
func ruleComment(userData []byte) string {
	i := 0
	for i+2 <= len(userData) {
		typ := userData[i]
		length := int(userData[i+1])
		if i+2+length > len(userData) {
			return ""
		}
		if typ == 0 {
			val := userData[i+2 : i+2+length]
			// Trim the terminating NUL if present.
			if n := len(val); n > 0 && val[n-1] == 0 {
				val = val[:n-1]
			}
			return string(val)
		}
		i += 2 + length
	}
	return ""
}
