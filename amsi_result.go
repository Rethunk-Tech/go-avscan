package avscan

import (
	"cmp"
	"errors"
	"io"
)

const (
	// amsiDetected is AMSI_RESULT_DETECTED: results at or above it are malware (AmsiResultIsMalware).
	amsiDetected = 32768
	// amsiBlockedStart and amsiBlockedEnd bound AMSI_RESULT_BLOCKED_BY_ADMIN_START..END: administrator policy blocks
	// the content on this machine, though the provider did not call it malware.
	amsiBlockedStart = 0x4000
	amsiBlockedEnd   = 0x4FFF
)

// amsiFlagged reports whether an AmsiScanBuffer result means the file must not pass: a detection, or content an
// administrator's policy blocks. Results between are the provider's risk estimate and are not a verdict.
func amsiFlagged(result uint32) bool {
	return result >= amsiDetected || (result >= amsiBlockedStart && result <= amsiBlockedEnd)
}

// amsiView hands out a file as consecutive buffers of up to fresh new bytes, each led by the last amsiOverlap bytes
// of the one before.
type amsiView struct {
	r       io.Reader
	buf     []byte
	fresh   int
	overlap int
	end     int
	done    bool
}

// newAMSIView sizes its buffer by the file, so a small file does not cost a whole chunk.
func newAMSIView(r io.Reader, size int64, chunk, overlap int) *amsiView {
	fresh := chunk
	if size >= 0 && size < int64(chunk) {
		fresh = int(size)
	}
	return &amsiView{r: r, buf: make([]byte, overlap+fresh), fresh: fresh, overlap: overlap}
}

// next returns the next buffer, valid until the following call. It returns io.EOF with an empty buffer when the file
// holds no more new bytes, and a buffer may come back together with the error that ended the file.
func (v *amsiView) next() ([]byte, error) {
	if v.done {
		return nil, io.EOF
	}
	keep := min(v.overlap, v.end)
	copy(v.buf, v.buf[v.end-keep:v.end])
	n, err := io.ReadFull(v.r, v.buf[keep:keep+v.fresh])
	if errors.Is(err, io.ErrUnexpectedEOF) {
		err = io.EOF
	}
	if err != nil {
		v.done = true
	}
	if n == 0 {
		return nil, cmp.Or(err, io.EOF)
	}
	v.end = keep + n
	return v.buf[:v.end], err
}
