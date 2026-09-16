package main

import (
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- RATE LIMITING ---
// Per-client token buckets, one limiter per API endpoint. Each client gets a
// burst of half a minute's allowance and refills continuously, so normal use
// (autosave at most every 1.5 s) never notices, while floods get 429s. The
// check runs before the request body is read, so rejected requests cost
// almost nothing.

const (
	// maxTrackedClients bounds limiter memory. Past it, unseen clients are let
	// through rather than tracked: a flood of distinct addresses must not lock
	// out legitimate new visitors.
	maxTrackedClients = 100_000
	sweepEvery        = 1024 // allow() calls between sweeps of idle buckets
)

type bucket struct {
	tokens float64
	last   time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	perSec  float64
	burst   float64
	buckets map[string]*bucket
	calls   int
	now     func() time.Time
}

// newRateLimiter returns nil (no limiting) when perMinute <= 0.
func newRateLimiter(perMinute int) *rateLimiter {
	if perMinute <= 0 {
		return nil
	}
	return &rateLimiter{
		perSec:  float64(perMinute) / 60,
		burst:   math.Max(1, float64(perMinute)/2),
		buckets: make(map[string]*bucket),
		now:     time.Now,
	}
}

// allow spends one token for key. When none is left it reports how long until
// the next token arrives.
func (l *rateLimiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if l.calls++; l.calls%sweepEvery == 0 {
		l.sweepLocked(now)
	}

	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxTrackedClients {
			return true, 0
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.perSec)
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / l.perSec * float64(time.Second))
}

// sweepLocked forgets clients whose bucket has refilled completely: tracking
// them again later starts from the same full state.
func (l *rateLimiter) sweepLocked(now time.Time) {
	for key, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.perSec >= l.burst {
			delete(l.buckets, key)
		}
	}
}

// rateLimited wraps an API handler with a limiter; a nil limiter disables it.
func rateLimited(l *rateLimiter, next http.HandlerFunc) http.HandlerFunc {
	if l == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if ok, wait := l.allow(clientKey(r)); !ok {
			secs := int(math.Ceil(wait.Seconds()))
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			writeJSON(w, http.StatusTooManyRequests,
				map[string]string{"error": "Too many requests. Wait a few seconds and try again."})
			return
		}
		next(w, r)
	}
}

// clientKey identifies the client a request is counted against.
//
// Without TRUST_PROXY_HEADER it is the TCP peer address. Behind a reverse
// proxy every request comes from the proxy, so the real address has to come
// from a header the proxy sets — only trust one when the server is reachable
// solely through that proxy (e.g. bound to 127.0.0.1 behind a tunnel), or
// clients could pick their own key.
//
// IPv6 clients are keyed by their /64, since a single host usually controls a
// whole /64 and could otherwise rotate addresses to dodge the limit.
func clientKey(r *http.Request) string {
	var raw string
	switch h := strings.TrimSpace(trustProxyHeader); {
	case h == "":
	case strings.EqualFold(h, "X-Forwarded-For"):
		// First entry = the original client as reported to the first proxy.
		raw, _, _ = strings.Cut(r.Header.Get("X-Forwarded-For"), ",")
	default:
		raw = r.Header.Get(h)
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		host, _, splitErr := net.SplitHostPort(r.RemoteAddr)
		if splitErr != nil {
			host = r.RemoteAddr
		}
		if addr, err = netip.ParseAddr(host); err != nil {
			return r.RemoteAddr
		}
	}
	addr = addr.Unmap()
	if addr.Is6() {
		prefix, _ := addr.Prefix(64)
		return prefix.String()
	}
	return addr.String()
}
