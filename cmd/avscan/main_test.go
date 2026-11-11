package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func invoke(ctx context.Context, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(ctx, args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func parseJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("json %q: %v", s, err)
	}
	want := []string{"dir", "scanner", "clean", "detection", "error"}
	if len(m) != len(want) {
		t.Fatalf("fields %v, want exactly %v", keys(m), want)
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing field %q in %v", k, m)
		}
	}
	return m
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func skipWindowsShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
}

func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestUsage(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
	}{
		{"no args", nil},
		{"two dirs", []string{dir, dir}},
		{"file instead of dir", []string{"-command", "true", file}},
		{"two scanners", []string{"-amsi", "-command", "true", dir}},
		{"no scanner", []string{dir}},
		{"bad clamd form", []string{"-clamd", "http://127.0.0.1:3310", dir}},
		{"bad clamd unix", []string{"-clamd", "unix:", dir}},
		{"bad clamd tcp", []string{"-clamd", "tcp:localhost", dir}},
		{"unknown flag", []string{"-bogus", dir}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, _ := invoke(t.Context(), tt.args...)
			if code != 2 {
				t.Fatalf("exit %d, want 2", code)
			}
		})
	}
}

func TestCommandRequiresPath(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := invoke(t.Context(), "-command", "true", dir)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if stdout != "" {
		t.Fatalf("stdout %q, want empty", stdout)
	}
	want := "error: avscan: command line has no {path}\n"
	if stderr != want {
		t.Fatalf("stderr %q, want %q", stderr, want)
	}
}

func TestCommandPathIsAbsolute(t *testing.T) {
	skipWindowsShell(t)
	parent := t.TempDir()
	dir := filepath.Join(parent, "--version")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	argvDir := t.TempDir()
	argvFile := filepath.Join(argvDir, "argv")
	script := writeScript(t, t.TempDir(), "argv.sh", "printf '%s\\n' \"$1\" > '"+argvFile+"'")
	t.Chdir(parent)
	code, _, stderr := invoke(t.Context(), "-command", "sh "+script+" {path}", "./--version")
	if code != 0 {
		t.Fatalf("exit %d, want 0; stderr=%q", code, stderr)
	}
	gotPath := readArgv(t, argvDir)
	if !filepath.IsAbs(gotPath) {
		t.Fatalf("path %q is not absolute", gotPath)
	}
	if filepath.Base(gotPath) != "--version" {
		t.Fatalf("path %q, want base --version", gotPath)
	}
}

func TestCommandClean(t *testing.T) {
	skipWindowsShell(t)
	script := writeScript(t, t.TempDir(), "clean.sh", "exit 0")
	dir := t.TempDir()
	code, stdout, stderr := invoke(t.Context(), "-command", "sh "+script+" {path}", dir)
	if code != 0 {
		t.Fatalf("exit %d, want 0; stderr=%q", code, stderr)
	}
	want := "clean: " + dir + "\n"
	if stdout != want {
		t.Fatalf("stdout %q, want %q", stdout, want)
	}
}

func TestCommandDetection(t *testing.T) {
	skipWindowsShell(t)
	script := writeScript(t, t.TempDir(), "detect.sh", "echo Eicar-Test-File\nexit 1")
	dir := t.TempDir()
	line := "sh " + script + " {path}"

	code, stdout, stderr := invoke(t.Context(), "-json", "-command", line, dir)
	if code != 1 {
		t.Fatalf("exit %d, want 1; stderr=%q stdout=%q", code, stderr, stdout)
	}
	m := parseJSON(t, stdout)
	if m["dir"] != dir || m["scanner"] != "command" {
		t.Fatalf("dir/scanner %v", m)
	}
	if m["clean"] != false {
		t.Fatalf("clean=%v, want false", m["clean"])
	}
	if m["error"] != nil {
		t.Fatalf("error=%v, want null", m["error"])
	}
	det, ok := m["detection"].(map[string]any)
	if !ok {
		t.Fatalf("detection=%v", m["detection"])
	}
	if det["name"] != "Eicar-Test-File" || det["file"] != "" || det["scanner"] != "sh" {
		t.Fatalf("detection fields %v", det)
	}

	code, stdout, stderr = invoke(t.Context(), "-command", line, dir)
	if code != 1 {
		t.Fatalf("human exit %d, want 1; stderr=%q", code, stderr)
	}
	want := "FOUND: Eicar-Test-File in  (sh)\n"
	if stdout != want {
		t.Fatalf("human stdout %q, want %q", stdout, want)
	}
}

func TestCommandUnexpected(t *testing.T) {
	// A program that does not start is a Command error, not a detection.
	missing := filepath.Join(t.TempDir(), "no-such-scanner")
	dir := t.TempDir()
	code, stdout, _ := invoke(t.Context(), "-json", "-command", missing+" {path}", dir)
	if code != 2 {
		t.Fatalf("exit %d, want 2; stdout=%q", code, stdout)
	}
	m := parseJSON(t, stdout)
	if m["clean"] != false {
		t.Fatalf("clean=%v, want false", m["clean"])
	}
	if m["error"] == nil {
		t.Fatal("error is null")
	}
}

func TestClamdMissingSocket(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "missing.sock")
	code, stdout, stderr := invoke(t.Context(), "-json", "-clamd", "unix:"+sock, dir)
	if code != 2 {
		t.Fatalf("exit %d, want 2; stderr=%q stdout=%q", code, stderr, stdout)
	}
	m := parseJSON(t, stdout)
	if m["clean"] != false || m["scanner"] != "clamd" || m["error"] == nil {
		t.Fatalf("got %v", m)
	}

	code, stdout, stderr = invoke(t.Context(), "-clamd", "unix:"+sock, dir)
	if code != 2 || stdout != "" || stderr == "" {
		t.Fatalf("human exit %d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestClamdTCPUnreachable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := invoke(t.Context(), "-json", "-clamd", "tcp:127.0.0.1:1", dir)
	if code != 2 {
		t.Fatalf("exit %d, want 2; stdout=%q", code, stdout)
	}
	m := parseJSON(t, stdout)
	if m["clean"] != false || m["error"] == nil {
		t.Fatalf("got %v", m)
	}
}

func TestAMSI(t *testing.T) {
	dir := t.TempDir()
	code, stdout, _ := invoke(t.Context(), "-json", "-amsi", dir)
	m := parseJSON(t, stdout)
	if runtime.GOOS != "windows" {
		if code != 2 || m["clean"] != false || m["error"] == nil {
			t.Fatalf("exit %d %v", code, m)
		}
		return
	}
	if code == 1 {
		t.Fatalf("clean dir flagged: %v", m)
	}
}

func TestTimeout(t *testing.T) {
	skipWindowsShell(t)
	script := writeScript(t, t.TempDir(), "slow.sh", "sleep 60\nexit 0")
	dir := t.TempDir()
	code, stdout, stderr := invoke(t.Context(), "-timeout", "1ms", "-json", "-command", "sh "+script+" {path}", dir)
	if code != 2 {
		t.Fatalf("exit %d, want 2; stdout=%q stderr=%q", code, stdout, stderr)
	}
	m := parseJSON(t, stdout)
	if m["clean"] != false {
		t.Fatalf("clean=%v, want false", m["clean"])
	}
}

// readArgv returns the first argument the argv.sh script recorded in dir.
func readArgv(t *testing.T, dir string) string {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open("argv")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(bytes.TrimSpace(got))
}

func TestCommandPathFollowsSymlinksBeforeDotDot(t *testing.T) {
	skipWindowsShell(t)
	base := t.TempDir()
	for _, d := range []string{"actual/child", "actual/scan", "scan"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(base, "actual", "child"), filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	argvDir := t.TempDir()
	script := writeScript(t, t.TempDir(), "argv.sh", "printf '%s\\n' \"$1\" > '"+filepath.Join(argvDir, "argv")+"'")
	t.Chdir(base)
	if code, _, stderr := invoke(t.Context(), "-command", "sh "+script+" {path}", "link/../scan"); code != 0 {
		t.Fatalf("exit %d, want 0; stderr=%q", code, stderr)
	}
	want, err := filepath.EvalSymlinks(filepath.Join(base, "actual", "scan"))
	if err != nil {
		t.Fatal(err)
	}
	if got := readArgv(t, argvDir); got != want {
		t.Fatalf("scanned %q, want %q (link/../scan through the symlink)", got, want)
	}
}
