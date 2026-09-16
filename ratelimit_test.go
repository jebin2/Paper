package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeClock lets bucket refill be tested without sleeping.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func limiterWithClock(perMinute int) (*rateLimiter, *fakeClock) {
	l := newRateLimiter(perMinute)
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l.now = clock.now
	return l, clock
}

func TestRateLimiterBurstAndRefill(t *testing.T) {
	l, clock := limiterWithClock(60) // 1/s, burst 30

	for i := 0; i < 30; i++ {
		if ok, _ := l.allow("a"); !ok {
			t.Fatalf("request %d within burst was limited", i)
		}
	}
	ok, wait := l.allow("a")
	if ok || wait <= 0 || wait > time.Second {
		t.Fatalf("request past burst: ok=%v wait=%v, want limited with wait in (0,1s]", ok, wait)
	}

	// Other clients are unaffected.
	if ok, _ := l.allow("b"); !ok {
		t.Fatal("a different client was limited")
	}

	clock.advance(time.Second)
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("token did not refill after 1s")
	}
	if ok, _ := l.allow("a"); ok {
		t.Fatal("more than one token refilled after 1s")
	}

	// A long idle period refills to the burst, not beyond it.
	clock.advance(time.Hour)
	for i := 0; i < 30; i++ {
		l.allow("a")
	}
	if ok, _ := l.allow("a"); ok {
		t.Fatal("bucket refilled past its burst size")
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	if newRateLimiter(0) != nil {
		t.Fatal("0/min should disable limiting")
	}
	called := false
	h := rateLimited(nil, func(http.ResponseWriter, *http.Request) { called = true })
	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/save", nil))
	if !called {
		t.Fatal("nil limiter must pass requests through")
	}
}

func TestRateLimiterSweepsIdleClients(t *testing.T) {
	l, clock := limiterWithClock(60)
	for i := 0; i < 500; i++ {
		l.allow("client-" + strconv.Itoa(i))
	}
	clock.advance(time.Minute) // everyone refilled
	for i := 0; i < sweepEvery; i++ {
		l.allow("active")
	}
	if n := len(l.buckets); n > 1 {
		t.Fatalf("%d buckets tracked after sweep, want only the active client", n)
	}
}

func TestRateLimiterFailsOpenWhenFull(t *testing.T) {
	l, _ := limiterWithClock(2) // burst 1
	for i := 0; len(l.buckets) < maxTrackedClients; i++ {
		l.buckets["client-"+strconv.Itoa(i)] = &bucket{tokens: 0, last: l.now()}
	}
	for i := 0; i < 5; i++ {
		if ok, _ := l.allow("brand-new-visitor"); !ok {
			t.Fatal("new client rejected while the table is full; should be let through untracked")
		}
	}
}

func TestClientKey(t *testing.T) {
	defer func(h string) { trustProxyHeader = h }(trustProxyHeader)

	req := func(remote string, headers map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/load", nil)
		r.RemoteAddr = remote
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}
	cases := []struct {
		name, trust, remote string
		headers             map[string]string
		want                string
	}{
		{"peer address", "", "203.0.113.7:5555", nil, "203.0.113.7"},
		{"header ignored unless trusted", "", "203.0.113.7:5555",
			map[string]string{"CF-Connecting-IP": "198.51.100.1"}, "203.0.113.7"},
		{"trusted CF header", "CF-Connecting-IP", "127.0.0.1:4000",
			map[string]string{"CF-Connecting-IP": "198.51.100.1"}, "198.51.100.1"},
		{"trusted header missing falls back", "CF-Connecting-IP", "127.0.0.1:4000", nil, "127.0.0.1"},
		{"trusted header garbage falls back", "CF-Connecting-IP", "127.0.0.1:4000",
			map[string]string{"CF-Connecting-IP": "not-an-ip"}, "127.0.0.1"},
		{"X-Forwarded-For first hop", "X-Forwarded-For", "10.0.0.2:80",
			map[string]string{"X-Forwarded-For": "198.51.100.9, 10.0.0.1"}, "198.51.100.9"},
		{"IPv6 grouped by /64", "", "[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:443", nil, "2001:db8:1:2::/64"},
		{"IPv4-mapped IPv6 unmapped", "CF-Connecting-IP", "127.0.0.1:1",
			map[string]string{"CF-Connecting-IP": "::ffff:198.51.100.3"}, "198.51.100.3"},
	}
	for _, c := range cases {
		trustProxyHeader = c.trust
		if got := clientKey(req(c.remote, c.headers)); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}

	// Two addresses in the same /64 share a bucket; different /64s don't.
	trustProxyHeader = ""
	a := clientKey(req("[2001:db8:1:2::1]:1", nil))
	b := clientKey(req("[2001:db8:1:2::ffff]:1", nil))
	c := clientKey(req("[2001:db8:1:3::1]:1", nil))
	if a != b || a == c {
		t.Fatalf("IPv6 /64 grouping wrong: %q %q %q", a, b, c)
	}
}

func TestAPIRateLimitedEndToEnd(t *testing.T) {
	resetConfig(t)
	saveRatePerMin = 4 // burst 2
	loadRatePerMin = 6 // burst 3
	trustProxyHeader = "CF-Connecting-IP"
	h := newHandler()

	post := func(path, ip string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"hash":"`+strings.Repeat("a", 32)+`"}`))
		r.RemoteAddr = "127.0.0.1:9999" // everything arrives via the tunnel
		r.Header.Set("CF-Connecting-IP", ip)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	for i := 0; i < 3; i++ {
		if w := post("/api/load", "198.51.100.1"); w.Code != http.StatusOK {
			t.Fatalf("load %d: got %d", i, w.Code)
		}
	}
	w := post("/api/load", "198.51.100.1")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("4th load: code=%d Retry-After=%q, want 429 with Retry-After", w.Code, w.Header().Get("Retry-After"))
	}
	var body map[string]string
	if json.Unmarshal(w.Body.Bytes(), &body); body["error"] == "" {
		t.Fatalf("429 body has no error message: %q", w.Body.String())
	}
	if w.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("429 response is missing security headers")
	}

	// Another visitor behind the same tunnel has their own budget.
	if w := post("/api/load", "198.51.100.2"); w.Code != http.StatusOK {
		t.Fatalf("other client's load: got %d", w.Code)
	}

	// Save has a separate budget from load: this client is out of load tokens
	// but can still reach save (400 = request reached the handler).
	for i := 0; i < 2; i++ {
		if w := post("/api/save", "198.51.100.1"); w.Code == http.StatusTooManyRequests {
			t.Fatalf("save %d limited by load budget", i)
		}
	}
	if w := post("/api/save", "198.51.100.1"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd save: got %d, want 429", w.Code)
	}
}
