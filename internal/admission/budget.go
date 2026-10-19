// Package admission provides nonblocking, process-wide resource budgets.
package admission

import (
	"errors"
	"sync"
)

var ErrCapacity = errors.New("tunnel request capacity reached")

type Budget struct {
	slots   chan struct{}
	observe func(float64)
}

func (b *Budget) InUse() int { return len(b.slots) }

type Lease struct {
	once   sync.Once
	budget *Budget
}

func New(limit int, observe func(float64)) *Budget {
	if limit < 1 {
		panic("admission: limit must be positive")
	}
	return &Budget{make(chan struct{}, limit), observe}
}
func (b *Budget) TryAcquire() (*Lease, bool) {
	select {
	case b.slots <- struct{}{}:
		if b.observe != nil {
			b.observe(1)
		}
		return &Lease{budget: b}, true
	default:
		return nil, false
	}
}
func (l *Lease) Release() {
	if l != nil {
		l.once.Do(func() {
			<-l.budget.slots
			if l.budget.observe != nil {
				l.budget.observe(-1)
			}
		})
	}
}
