//go:build !windows

package avscan

import "context"

// SecurityCenterProducts lists the display names Windows Security Center holds for registered antivirus products. Off
// Windows there is none and it returns [ErrNoScanner].
func SecurityCenterProducts(context.Context) ([]string, error) {
	return nil, ErrNoScanner
}
