package avscan

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// A clamd reply is untrusted: whatever it says, the detection name reaching the caller is short, valid UTF-8 and
// free of control characters.
func FuzzParseReply(f *testing.F) {
	for _, seed := range []string{
		"stream: OK\x00",
		"stream: Eicar-Test-Signature FOUND\x00",
		"INSTREAM size limit exceeded. ERROR\x00",
		"stream: \x1b[31mred\x07 FOUND\x00",
		"",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, reply []byte) {
		name, err := parseReply(strings.NewReader(string(reply)))
		if err != nil && name != "" {
			t.Fatalf("name %q returned with error %v", name, err)
		}
		if len(name) > maxNameLen || !utf8.ValidString(name) {
			t.Fatalf("name %q is too long or not UTF-8", name)
		}
		if strings.IndexFunc(name, unicode.IsControl) >= 0 {
			t.Fatalf("name %q carries a control character", name)
		}
	})
}

// Quotes only group: no part of a split command line keeps a double quote.
func FuzzSplitCommand(f *testing.F) {
	for _, seed := range []string{`clamscan --no-summary "{path}"`, `"C:\Program Files\av\scan.exe" --quiet`, `a  "b c`, ``} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		for _, part := range splitCommand(line) {
			if strings.ContainsRune(part, '"') {
				t.Fatalf("part %q of %q keeps a quote", part, line)
			}
		}
	})
}
