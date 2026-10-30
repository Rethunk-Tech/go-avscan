//go:build windows

package avscan

import (
	"context"
	"os/exec"
	"strings"

	"github.com/Rethunk-Tech/go-desktopenv/nowindow"
)

// SecurityCenterProducts lists the display names Windows Security Center holds for registered antivirus products. An
// unreadable Security Center (Windows Server has none) is an error, and a readable one with no product is
// [ErrNoScanner].
func SecurityCenterProducts(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"$ErrorActionPreference = 'Stop'; (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct).displayName")
	nowindow.Set(cmd)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	// One name per line, so a name that contains ", " survives.
	var names []string
	for line := range strings.SplitSeq(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			names = append(names, line)
		}
	}
	if len(names) == 0 {
		return nil, ErrNoScanner
	}
	return names, nil
}
