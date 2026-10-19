// Package tunnel contains transport security and bounded stream lifecycle helpers.
package tunnel

import (
	"context"
	"github.com/quic-go/quic-go"
	"io"
	"sync"
	"time"
)

const (
	ControlAuthority = "wanopt-control.invalid:443"
	ProxyAuthority   = "wanopt-stream.invalid:443"
	VersionHeader    = "Wanopt-Protocol"
)

// Stream is the common lifecycle of HTTP/3 request and response streams.
// Close sends FIN. Abort terminates both halves when no further data is wanted.
type Stream interface {
	io.ReadWriteCloser
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

func Abort(s Stream) { s.CancelRead(0x10c); s.CancelWrite(0x10c) }

// BindContext interrupts blocked operations. Stop is idempotent and joins an
// already running callback before ownership is transferred to another caller.
func BindContext(ctx context.Context, s Stream) func() {
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.SetDeadline(deadline)
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { Abort(s); close(done) })
	var once sync.Once
	return func() {
		once.Do(func() {
			if !stop() {
				<-done
			}
		})
	}
}
