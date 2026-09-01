// Package validate contains contract-local validation primitives shared by
// the public review boundary. Its internal path deliberately keeps these
// helpers out of the public API.
package validate

import (
	"regexp"
	"strings"

	"github.com/charlesnpx/witness/contract/diag"
	"github.com/charlesnpx/witness/contract/digest"
)

var stableIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

func ValidDigest(value string) bool {
	if !strings.HasPrefix(value, digest.Prefix) {
		return false
	}
	hex := strings.TrimPrefix(value, digest.Prefix)
	if len(hex) != 64 {
		return false
	}
	for _, r := range hex {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

func RequireDigest(diagnostics *[]diag.Diagnostic, path string, field string, value string, code string) {
	if !ValidDigest(value) {
		*diagnostics = append(*diagnostics, Diagnostic(
			code,
			field+" must be a relay-root-digests-v1 sha256 digest.",
			path,
			map[string]any{"value": value},
		))
	}
}

func RequireString(diagnostics *[]diag.Diagnostic, path string, field string, value string, code string) {
	if strings.TrimSpace(value) == "" {
		*diagnostics = append(*diagnostics, Diagnostic(
			code,
			field+" is required.",
			path,
			nil,
		))
	}
}

func RequireStableID(diagnostics *[]diag.Diagnostic, path string, field string, value string, code string) {
	if !stableIDPattern.MatchString(value) {
		*diagnostics = append(*diagnostics, Diagnostic(
			code,
			field+" requires a stable ID.",
			path,
			map[string]any{"id": value},
		))
	}
}

func RequireEnum(diagnostics *[]diag.Diagnostic, path string, field string, value string, allowed map[string]bool, code string) {
	if !allowed[value] {
		*diagnostics = append(*diagnostics, Diagnostic(
			code,
			field+" has an unsupported value.",
			path,
			map[string]any{"value": value},
		))
	}
}

func Diagnostic(code string, message string, path string, details map[string]any) diag.Diagnostic {
	return diag.Diagnostic{
		Code:    code,
		Message: message,
		Path:    path,
		Details: details,
	}
}

func PrefixDiagnostics(prefix string, diagnostics []diag.Diagnostic) []diag.Diagnostic {
	if len(diagnostics) == 0 {
		return nil
	}
	prefixed := make([]diag.Diagnostic, len(diagnostics))
	for index, item := range diagnostics {
		prefixed[index] = item
		prefixed[index].Path = prefix + item.Path
	}
	return prefixed
}

func AppendPointer(path string, segment string) string {
	escaped := strings.ReplaceAll(segment, "~", "~0")
	escaped = strings.ReplaceAll(escaped, "/", "~1")
	return path + "/" + escaped
}

func StringSet(values ...string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func CompareDigest(diagnostics *[]diag.Diagnostic, path string, label string, actual string, expected string, code string) {
	if actual != expected {
		*diagnostics = append(*diagnostics, Diagnostic(
			code,
			label+" digest mismatch.",
			path,
			map[string]any{"actual": actual, "expected": expected},
		))
	}
}

func IdentityPresent(identity map[string]any) bool {
	return len(identity) > 0
}
