//go:build windows

package avscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	amsiDLL          = windows.NewLazySystemDLL("amsi.dll")
	amsiInitialize   = amsiDLL.NewProc("AmsiInitialize")
	amsiUninitialize = amsiDLL.NewProc("AmsiUninitialize")
	amsiOpenSession  = amsiDLL.NewProc("AmsiOpenSession")
	amsiCloseSession = amsiDLL.NewProc("AmsiCloseSession")
	amsiScanBuffer   = amsiDLL.NewProc("AmsiScanBuffer")
)

// amsiNotReady is HRESULT_FROM_WIN32(ERROR_NOT_READY), which AmsiScanBuffer returns when no antivirus is registered
// as the AMSI provider.
const amsiNotReady = 0x80070015

const (
	// amsiChunk is how much new file data one AmsiScanBuffer call sees.
	amsiChunk = 32 << 20
	// amsiOverlap is how much of the previous chunk's end the next call sees again, so a pattern that straddles the
	// boundary is not split between two buffers.
	amsiOverlap = 1 << 20
)

// AMSI is the Windows Antimalware Scan Interface: each file goes to the antivirus registered as the AMSI provider,
// Defender or a third party. AppName is the name AmsiInitialize registers; "" uses the executable's base name. A
// missing amsi.dll, a failed AmsiInitialize or no registered provider is [ErrNoScanner]. A file Windows refuses to open
// as infected counts as a detection. AMSI never names the threat, so Name is "".
type AMSI struct{ AppName string }

// Scan hands every file under dir to the provider and returns the first detection.
func (a AMSI) Scan(ctx context.Context, dir string) (Detection, bool, error) {
	if err := amsiDLL.Load(); err != nil {
		return Detection{}, false, fmt.Errorf("%w: amsi.dll: %w", ErrNoScanner, err)
	}
	name := a.AppName
	if name == "" {
		exe, err := os.Executable()
		if err != nil {
			return Detection{}, false, err
		}
		name = filepath.Base(exe)
	}
	app, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return Detection{}, false, err
	}
	var actx uintptr
	if hr, _, _ := amsiInitialize.Call(uintptr(unsafe.Pointer(app)), uintptr(unsafe.Pointer(&actx))); hr != 0 { //nolint:gosec // G103: the conversion stays in the Call so its //go:uintptrescapes keeps the target alive
		return Detection{}, false, fmt.Errorf("%w: AmsiInitialize HRESULT 0x%x", ErrNoScanner, hr)
	}
	defer func() { _, _, _ = amsiUninitialize.Call(actx) }()
	var session uintptr
	if hr, _, _ := amsiOpenSession.Call(actx, uintptr(unsafe.Pointer(&session))); hr != 0 { //nolint:gosec // G103: the conversion stays in the Call so its //go:uintptrescapes keeps the target alive
		return Detection{}, false, fmt.Errorf("AmsiOpenSession: HRESULT 0x%x", hr)
	}
	defer func() { _, _, _ = amsiCloseSession.Call(actx, session) }()
	// The no-provider answer only comes from AmsiScanBuffer, which an empty folder never reaches, so probe once.
	probe := []byte{0}
	var probeResult uint32
	hr, _, _ := amsiScanBuffer.Call(actx, uintptr(unsafe.Pointer(&probe[0])), 1, 0, session, uintptr(unsafe.Pointer(&probeResult))) //nolint:gosec // G103: the conversion stays in the Call so its //go:uintptrescapes keeps the target alive
	if hr&0xFFFFFFFF == amsiNotReady {
		return Detection{}, false, fmt.Errorf("%w: AmsiScanBuffer: no provider answered", ErrNoScanner)
	}
	if hr != 0 {
		return Detection{}, false, fmt.Errorf("AmsiScanBuffer: HRESULT 0x%x", hr)
	}
	var found Detection
	var hit bool
	errStop := errors.New("stop")
	err = files(ctx, dir, func(root *os.Root, rel string) error {
		flagged, err := scanFileAMSI(ctx, actx, session, root, rel)
		if err != nil {
			return err
		}
		if flagged {
			found, hit = Detection{File: rel, Scanner: "AMSI"}, true
			return errStop
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStop) {
		return Detection{}, false, err
	}
	return found, hit, nil
}

func scanFileAMSI(ctx context.Context, actx, session uintptr, root *os.Root, rel string) (bool, error) {
	in, err := openRegular(root, rel)
	if errors.Is(err, windows.ERROR_VIRUS_INFECTED) || errors.Is(err, windows.ERROR_VIRUS_DELETED) {
		return true, nil
	}
	if errors.Is(err, errNotRegular) {
		return false, fmt.Errorf("%s: %w", rel, err)
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = in.Close() }()
	name, err := windows.UTF16PtrFromString(rel)
	if err != nil {
		return false, err
	}
	fi, err := in.Stat()
	if err != nil {
		return false, err
	}
	size := fi.Size()
	view := newAMSIView(in, size, amsiChunk, amsiOverlap)
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		buf, err := view.next()
		if len(buf) > 0 {
			var result uint32
			hr, _, _ := amsiScanBuffer.Call(actx, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), //nolint:gosec // G103: the conversion stays in the Call so its //go:uintptrescapes keeps the target alive
				uintptr(unsafe.Pointer(name)), session, uintptr(unsafe.Pointer(&result))) //nolint:gosec // G103: the conversion stays in the Call so its //go:uintptrescapes keeps the target alive
			if hr&0xFFFFFFFF == amsiNotReady {
				return false, fmt.Errorf("%w: AmsiScanBuffer: no provider answered", ErrNoScanner)
			}
			if hr != 0 {
				return false, fmt.Errorf("AmsiScanBuffer: HRESULT 0x%x", hr)
			}
			if amsiFlagged(result) {
				return true, nil
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return false, nil
			}
			return false, err
		}
	}
}
