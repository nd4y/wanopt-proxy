package metrics

import (
	"context"
	"errors"
	"testing"
	"time"
	"wanopt/internal/compress"
)

func TestOperationalMetricsBoundLabelsAndAccountCompression(t *testing.T) {
	m := New("test")
	for i := 0; i < 100; i++ {
		m.Rejected("untrusted-name")
		m.Failure("untrusted-stage", errors.New("untrusted-message"))
		m.Observe("untrusted-stage", time.Millisecond)
	}
	m.Failure("dial", context.DeadlineExceeded)
	m.Compression(compress.Stats{InputBytes: 100, OutputBytes: 30, Attempted: 3, Skipped: 2, Compressed: 1, EncodeTime: time.Millisecond})
	families, err := m.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == "wanopt_admission_rejected_total" {
			if len(f.Metric) != 1 || f.Metric[0].GetCounter().GetValue() != 100 {
				t.Fatal("unbounded rejection labels")
			}
		}
		if f.GetName() == "wanopt_compression_input_bytes_total" && f.Metric[0].GetCounter().GetValue() != 100 {
			t.Fatal("wrong codec accounting")
		}
	}
}
