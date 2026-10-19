package admission

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestBudgetConcurrentRelease(t *testing.T) {
	var active atomic.Int64
	b := New(3, func(n float64) { active.Add(int64(n)) })
	leases := make([]*Lease, 3)
	for i := range leases {
		var ok bool
		leases[i], ok = b.TryAcquire()
		if !ok {
			t.Fatal("early rejection")
		}
	}
	if _, ok := b.TryAcquire(); ok {
		t.Fatal("budget exceeded")
	}
	var wg sync.WaitGroup
	for range 20 {
		for _, l := range leases {
			wg.Go(l.Release)
		}
	}
	wg.Wait()
	if active.Load() != 0 || len(b.slots) != 0 {
		t.Fatal("lease leak or double release")
	}
	l, ok := b.TryAcquire()
	if !ok {
		t.Fatal("released slot unavailable")
	}
	l.Release()
}
