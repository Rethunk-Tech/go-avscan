//go:build !windows

package avscan

import "context"

// AMSI is the Windows Antimalware Scan Interface: each file goes to the antivirus registered as the AMSI provider,
// Defender or a third party. AppName is the name AmsiInitialize registers; "" uses the executable's base name. Off
// Windows there is no provider and Scan returns [ErrNoScanner].
type AMSI struct{ AppName string }

// Scan reports [ErrNoScanner].
func (AMSI) Scan(context.Context, string) (Detection, bool, error) {
	return Detection{}, false, ErrNoScanner
}
