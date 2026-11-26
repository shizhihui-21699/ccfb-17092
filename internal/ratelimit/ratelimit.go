// Package ratelimit 提供全局/每目标两级并发与速率控制，
// 防止几百个协程把内网服务打挂。
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter 组合了全局令牌桶与信号量。
type Limiter struct {
	tokens  chan struct{} // 全局并发信号量
	rate    *tokenBucket  // 全局 QPS 限速
	perHost *hostGate     // 每目标并发
}

// Config 是限速配置。
type Config struct {
	GlobalConcurrency int // 全局最大并发
	HostConcurrency   int // 单主机最大并发
	QPS               int // 全局每秒请求数（0 表示不限）
}

// New 构造限流器。
func New(cfg Config) *Limiter {
	if cfg.GlobalConcurrency <= 0 {
		cfg.GlobalConcurrency = 50
	}
	if cfg.HostConcurrency <= 0 {
		cfg.HostConcurrency = 4
	}
	l := &Limiter{
		tokens:  make(chan struct{}, cfg.GlobalConcurrency),
		perHost: newHostGate(cfg.HostConcurrency),
	}
	if cfg.QPS > 0 {
		l.rate = newTokenBucket(cfg.QPS)
	}
	return l
}

// Acquire 取得一个调用额度，返回释放函数。
func (l *Limiter) Acquire(ctx context.Context, host string) (func(), error) {
	select {
	case l.tokens <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	hostRelease := l.perHost.acquire(host)
	if l.rate != nil {
		if err := l.rate.wait(ctx); err != nil {
			hostRelease()
			<-l.tokens
			return nil, err
		}
	}
	return func() {
		hostRelease()
		<-l.tokens
	}, nil
}

// ---- 每主机信号量 ----

type hostGate struct {
	mu    sync.Mutex
	max   int
	gates map[string]chan struct{}
}

func newHostGate(max int) *hostGate {
	return &hostGate{max: max, gates: make(map[string]chan struct{})}
}

func (g *hostGate) acquire(host string) func() {
	g.mu.Lock()
	ch, ok := g.gates[host]
	if !ok {
		ch = make(chan struct{}, g.max)
		g.gates[host] = ch
	}
	g.mu.Unlock()
	ch <- struct{}{}
	return func() { <-ch }
}

// ---- 简单令牌桶（每秒补充 qps 个令牌）----

type tokenBucket struct {
	ch   chan struct{}
	stop chan struct{}
}

func newTokenBucket(qps int) *tokenBucket {
	b := &tokenBucket{
		ch:   make(chan struct{}, qps),
		stop: make(chan struct{}),
	}
	for i := 0; i < qps; i++ {
		b.ch <- struct{}{}
	}
	go b.fill(qps)
	return b
}

func (b *tokenBucket) fill(qps int) {
	interval := time.Second / time.Duration(qps)
	if interval <= 0 {
		interval = time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-t.C:
			select {
			case b.ch <- struct{}{}:
			default: // 桶满丢弃
			}
		}
	}
}

func (b *tokenBucket) wait(ctx context.Context) error {
	select {
	case <-b.ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stop 停止后台补充协程。
func (l *Limiter) Stop() {
	if l.rate != nil {
		close(l.rate.stop)
	}
}
