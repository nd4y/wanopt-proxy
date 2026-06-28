package tunnel

import (
	"context"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
)

// Default flow-control windows. Large connection/stream receive windows are the
// single most important throughput lever on high bandwidth-delay-product (WAN)
// links, since they cap how much data can be in flight before an ACK.
//
// Note on congestion control: quic-go v0.48 uses CUBIC internally and does not
// expose a public switch for BBR, so we cannot select it here. The receive
// window tuning below is what actually unlocks throughput on fat, long links.
const (
	defaultMaxStreamRecvWindow = 16 << 20 // 16 MiB
	defaultMaxConnRecvWindow   = 24 << 20 // 24 MiB
	initialStreamRecvWindow    = 512 << 10
	initialConnRecvWindow      = 768 << 10
)

// QUICOptions configures NewQUICConfig.
type QUICOptions struct {
	EnableDatagrams     bool
	IdleTimeout         time.Duration
	MaxStreamRecvWindow uint64 // 0 -> default
	MaxConnRecvWindow   uint64 // 0 -> default
	Allow0RTT           bool   // server side
	TokenStore          quic.TokenStore
	Tracer              func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer
}

// NewQUICConfig builds a tuned *quic.Config shared by client and server.
func NewQUICConfig(o QUICOptions) *quic.Config {
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 60 * time.Second
	}
	if o.MaxStreamRecvWindow == 0 {
		o.MaxStreamRecvWindow = defaultMaxStreamRecvWindow
	}
	if o.MaxConnRecvWindow == 0 {
		o.MaxConnRecvWindow = defaultMaxConnRecvWindow
	}
	return &quic.Config{
		EnableDatagrams:                o.EnableDatagrams,
		MaxIdleTimeout:                 o.IdleTimeout,
		KeepAlivePeriod:                o.IdleTimeout / 3,
		InitialStreamReceiveWindow:     initialStreamRecvWindow,
		MaxStreamReceiveWindow:         o.MaxStreamRecvWindow,
		InitialConnectionReceiveWindow: initialConnRecvWindow,
		MaxConnectionReceiveWindow:     o.MaxConnRecvWindow,
		Allow0RTT:                      o.Allow0RTT,
		TokenStore:                     o.TokenStore,
		Tracer:                         o.Tracer,
	}
}
