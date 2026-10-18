package metrics

import (
	"context"
	"errors"
	"net"
	"time"
	"wanopt/internal/admission"
	"wanopt/internal/compress"
)

func (m *Metrics) BudgetChange(codec bool) func(float64) {
	if m == nil {
		return nil
	}
	if codec {
		return m.CodecBudget.Add
	}
	return m.ActiveBudget.Add
}
func (m *Metrics) Rejected(resource string) {
	if m == nil {
		return
	}
	switch resource {
	case "stream", "connection", "pending":
	default:
		resource = "other"
	}
	m.rejected.WithLabelValues(resource).Inc()
}
func (m *Metrics) CodecFallback() {
	if m != nil {
		m.codecFallback.Inc()
	}
}
func (m *Metrics) Failure(stage string, err error) {
	if m == nil || err == nil {
		return
	}
	switch stage {
	case "connect", "auth", "open", "dial", "relay", "heartbeat":
	default:
		stage = "other"
	}
	reason := "error"
	var ne net.Error
	if errors.Is(err, admission.ErrCapacity) {
		reason = "capacity"
	} else if errors.Is(err, context.Canceled) {
		reason = "canceled"
	} else if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		reason = "timeout"
	}
	m.failures.WithLabelValues(stage, reason).Inc()
}
func (m *Metrics) Compression(s compress.Stats) {
	if m == nil {
		return
	}
	m.codecInput.Add(float64(s.InputBytes))
	m.codecOutput.Add(float64(s.OutputBytes))
	m.codecAttempts.Add(float64(s.Attempted))
	m.codecSkipped.Add(float64(s.Skipped))
	m.codecCompressed.Add(float64(s.Compressed))
	m.codecSeconds.Add(s.EncodeTime.Seconds())
}

func (m *Metrics) Controller(mode string) {
	if m == nil {
		return
	}
	if mode != "bbr" {
		mode = "reno"
	}
	m.controller.WithLabelValues(mode).Set(1)
}
func (m *Metrics) Observe(stage string, elapsed time.Duration) {
	if m == nil {
		return
	}
	switch stage {
	case "open", "auth", "heartbeat":
	default:
		stage = "other"
	}
	m.latency.WithLabelValues(stage).Observe(elapsed.Seconds())
}
