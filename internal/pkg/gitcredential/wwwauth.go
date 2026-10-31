package gitcredential

import "strings"

// ResourceMetadata returns the RFC 9728 §5 resource_metadata URL from the
// first Bearer challenge that carries one, across the request's
// WWW-Authenticate headers in order, or "" if there is none.
func (r Request) ResourceMetadata() string {
	for _, header := range r.WWWAuthenticate {
		for _, c := range parseChallenges(header) {
			if strings.EqualFold(c.scheme, "bearer") {
				if u := c.params["resource_metadata"]; u != "" {
					return u
				}
			}
		}
	}
	return ""
}

// challenge is one authentication challenge from a WWW-Authenticate header.
type challenge struct {
	scheme string
	params map[string]string // names lowercased
}

// parseChallenges parses a WWW-Authenticate header value into its
// challenges (RFC 9110 §11.6.1): a scheme followed by comma-separated
// name=value parameters, where a value is a token or a quoted string, and
// several challenges may share one header. It is lenient: anything it can't
// make sense of is skipped rather than failing the whole header.
func parseChallenges(h string) []challenge {
	var challenges []challenge
	i := 0
	for i < len(h) {
		i = skip(h, i, " \t,")
		name, next := readToken(h, i)
		if name == "" {
			i++ // not a token character; skip it
			continue
		}
		j := skip(h, next, " \t")
		if j < len(h) && h[j] == '=' {
			// A parameter of the current challenge.
			k := skip(h, j+1, " \t")
			var value string
			if k < len(h) && h[k] == '"' {
				value, next = readQuoted(h, k)
			} else {
				value, next = readToken(h, k)
			}
			if n := len(challenges); n > 0 {
				challenges[n-1].params[strings.ToLower(name)] = value
			}
			i = next
			continue
		}
		// A new challenge's scheme.
		challenges = append(challenges, challenge{scheme: name, params: map[string]string{}})
		i = j
	}
	return challenges
}

func skip(s string, i int, chars string) int {
	for i < len(s) && strings.IndexByte(chars, s[i]) >= 0 {
		i++
	}
	return i
}

// readToken reads an RFC 9110 token starting at i.
func readToken(s string, i int) (string, int) {
	start := i
	for i < len(s) && isTokenChar(s[i]) {
		i++
	}
	return s[start:i], i
}

func isTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// readQuoted reads a quoted string starting at the opening quote at i,
// unescaping backslash pairs. An unterminated string runs to the end.
func readQuoted(s string, i int) (string, int) {
	var b strings.Builder
	for i++; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			}
		case '"':
			return b.String(), i + 1
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String(), i
}
