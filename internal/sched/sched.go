// Package sched provides the bounded concurrency and rate control for a scan.
//
// Two limits apply: a worker pool bounds simultaneous in-flight probes, and a
// token bucket bounds requests per second. The bucket matters on a shared
// internal network: a few hundred services in a /24 can turn an unbounded
// sweep into a realistic SYN flood, and scan-induced outages are their own
// incident.
package sched

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// Scheduler runs functions with bounded parallelism and rate.
type Scheduler struct {
	limit   *rate.Limiter
	sem     chan struct{}
	limiter bool
	wg      sync.WaitGroup
}

// New builds a scheduler. ratePerSec <= 0 disables rate limiting (concurrency
// alone still applies).
func New(concurrency int, ratePerSec float64) *Scheduler {
	if concurrency < 1 {
		concurrency = 1
	}
	s := &Scheduler{sem: make(chan struct{}, concurrency)}
	if ratePerSec > 0 {
		// Burst of one second's worth of tokens, so a small scan is not forced
		// into an artificially slow drip.
		burst := int(ratePerSec)
		if burst < 1 {
			burst = 1
		}
		s.limit = rate.NewLimiter(rate.Limit(ratePerSec), burst)
		s.limiter = true
	}
	return s
}

// Go schedules fn. It blocks while the concurrency slot or rate token is
// unavailable, and respects ctx cancellation while waiting.
func (s *Scheduler) Go(ctx context.Context, fn func()) bool {
	if s.limiter {
		if err := s.limit.Wait(ctx); err != nil {
			return false
		}
	}
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	s.wg.Add(1)
	go func() {
		defer func() {
			<-s.sem
			s.wg.Done()
		}()
		fn()
	}()
	return true
}

// Wait blocks until every scheduled function returns.
func (s *Scheduler) Wait() { s.wg.Wait() }
