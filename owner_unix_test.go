//go:build unix

package avscan

import "testing"

func TestDarwinUIDMinFallbackExcludesHumanAccounts(t *testing.T) {
	const firstMacUser = 501
	if uidMinFallback("darwin") > firstMacUser {
		t.Fatalf("darwin UID_MIN fallback = %d; uid %d is a regular macOS user and must not be a system account", uidMinFallback("darwin"), firstMacUser)
	}
}
