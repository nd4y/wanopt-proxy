package tunnel

import (
	"github.com/quic-go/quic-go"
	"time"
)

const (
	defaultMaxStreamRecvWindow = 16 << 20
	defaultMaxConnRecvWindow   = 24 << 20
	initialStreamRecvWindow    = 512 << 10
	initialConnRecvWindow      = 768 << 10
)

type QUICOptions struct {
	CongestionControl   string
	EnableDatagrams     bool
	IdleTimeout         time.Duration
	HandshakeTimeout    time.Duration
	MaxStreamRecvWindow uint64
	MaxConnRecvWindow   uint64
	MaxIncomingStreams  int64
	TokenStore          quic.TokenStore
	// Allow0RTT is retained for source compatibility. Early data is never accepted.
	Allow0RTT bool
}

func NewQUICConfig(o QUICOptions) *quic.Config {
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 60 * time.Second
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 10 * time.Second
	}
	if o.MaxStreamRecvWindow == 0 {
		o.MaxStreamRecvWindow = defaultMaxStreamRecvWindow
	}
	if o.MaxConnRecvWindow == 0 {
		o.MaxConnRecvWindow = defaultMaxConnRecvWindow
	}
	if o.MaxIncomingStreams == 0 {
		o.MaxIncomingStreams = 128
	}
	return configureCongestion(&quic.Config{
		EnableDatagrams:      o.EnableDatagrams,
		HandshakeIdleTimeout: o.HandshakeTimeout / 2,
		MaxIdleTimeout:       o.IdleTimeout, KeepAlivePeriod: o.IdleTimeout / 3,
		InitialStreamReceiveWindow:     min(initialStreamRecvWindow, o.MaxStreamRecvWindow),
		MaxStreamReceiveWindow:         o.MaxStreamRecvWindow,
		InitialConnectionReceiveWindow: min(initialConnRecvWindow, o.MaxConnRecvWindow),
		MaxConnectionReceiveWindow:     o.MaxConnRecvWindow,
		MaxIncomingStreams:             o.MaxIncomingStreams, MaxIncomingUniStreams: 3,
		Allow0RTT: false, TokenStore: o.TokenStore,
	}, o.CongestionControl)
}
