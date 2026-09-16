package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// resetConfig points the package-level config at known values and a fresh,
// per-test temp data dir. It returns that dir.
func resetConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dataDir = dir
	maxTotalSizeMB = 100
	purgeToSizeMB = 80
	ageLimitDays = 2
	maxContentSizeMB = 1
	cleanupInterval = 15 * time.Minute
	corsOrigins = ""
	staticDir = dir
	maxContentBytes = int64(maxContentSizeMB) * 1024 * 1024
	maxRequestBytes = maxContentBytes + 64*1024
	usedBytes = 0
	saveRatePerMin = 0 // limiting has its own tests; keep load/concurrency tests unthrottled
	loadRatePerMin = 0
	trustProxyHeader = ""
	return dir
}

type testApp struct {
	h   http.Handler
	dir string
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()
	dir := resetConfig(t)
	return &testApp{h: newHandler(), dir: dir}
}

func doRequest(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

var (
	testToken    = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("t", tokenBytes)))
	otherToken   = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("o", tokenBytes)))
	testSalt     = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", saltBytes)))
	otherSalt    = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", saltBytes)))
	savePayloadT = func(hash, content, token, salt, base string) string {
		payload, _ := json.Marshal(map[string]string{
			"hash": hash, "content": content, "token": token, "salt": salt, "base": base,
		})
		return string(payload)
	}
)

// saveNote saves as the note's owner (default test token and salt), based on
// the latest stored version — i.e. a well-behaved single tab.
func saveNote(t *testing.T, h http.Handler, hash, content string) int {
	t.Helper()
	return saveNoteAs(t, h, hash, content, testToken, testSalt)
}

func saveNoteAs(t *testing.T, h http.Handler, hash, content, token, salt string) int {
	t.Helper()
	_, cur := loadNote(t, h, hash)
	return saveNoteBased(t, h, hash, content, token, salt, cur.Version)
}

func saveNoteBased(t *testing.T, h http.Handler, hash, content, token, salt, base string) int {
	t.Helper()
	return doRequest(h, http.MethodPost, "/api/save", savePayloadT(hash, content, token, salt, base)).Code
}

// dataFiles lists every file in the data dir (for "did this write?" checks).
func dataFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

type loadResp struct {
	Content string `json:"content"`
	Salt    string `json:"salt"`
	Version string `json:"version"`
}

func loadNote(t *testing.T, h http.Handler, hash string) (int, loadResp) {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"hash": hash})
	w := doRequest(h, http.MethodPost, "/api/load", string(payload))
	var resp loadResp
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("bad load response %q: %v", w.Body.String(), err)
		}
	}
	return w.Code, resp
}

func writeContentFile(t *testing.T, dir, hash, content string) string {
	t.Helper()
	path := filepath.Join(dir, hash+"_content.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// --- Basic / normal flow ---

func TestHealth(t *testing.T) {
	app := newTestApp(t)
	w := doRequest(app.h, http.MethodGet, "/health", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "ok") {
		t.Fatalf("health: got %d %q", w.Code, w.Body.String())
	}
}

func TestIndexServesFrontend(t *testing.T) {
	dir := resetConfig(t)
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<b>frontend</b>"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &testApp{h: newHandler(), dir: dir}
	w := doRequest(app.h, http.MethodGet, "/", "")
	if w.Code != http.StatusOK || w.Body.String() != "<b>frontend</b>" {
		t.Fatalf("index: got %d %q", w.Code, w.Body.String())
	}
	// anything else under "/" is a 404
	for _, path := range []string{"/other", "/api"} {
		if w := doRequest(app.h, http.MethodGet, path, ""); w.Code != http.StatusNotFound {
			t.Fatalf("%s: got %d, want 404", path, w.Code)
		}
	}
}

func TestAppJSServed(t *testing.T) {
	dir := resetConfig(t)
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log('hi')"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &testApp{h: newHandler(), dir: dir}
	w := doRequest(app.h, http.MethodGet, "/app.js", "")
	if w.Code != http.StatusOK || w.Body.String() != "console.log('hi')" {
		t.Fatalf("app.js: got %d %q", w.Code, w.Body.String())
	}
}

func TestSecurityHeaders(t *testing.T) {
	app := newTestApp(t)
	w := doRequest(app.h, http.MethodGet, "/health", "")
	for _, h := range []string{
		"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy",
		"Permissions-Policy", "X-Frame-Options", "Strict-Transport-Security",
	} {
		if w.Header().Get(h) == "" {
			t.Fatalf("missing security header %s", h)
		}
	}
	csp := w.Header().Get("Content-Security-Policy")
	scriptPart := strings.Split(csp, ";")
	for _, p := range scriptPart {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "script-src") && strings.Contains(p, "unsafe-inline") {
			t.Fatalf("script-src must not allow 'unsafe-inline': %q", csp)
		}
	}
	if !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("script-src 'self' missing from CSP: %q", csp)
	}
	if strings.Contains(csp, "http") {
		t.Fatalf("CSP allows a third-party origin: %q", csp)
	}
}

func TestFontsServed(t *testing.T) {
	dir := resetConfig(t)
	if err := os.MkdirAll(filepath.Join(dir, "fonts"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"a.woff2": "font", "OFL.txt": "license"} {
		if err := os.WriteFile(filepath.Join(dir, "fonts", name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h := newHandler()

	w := doRequest(h, http.MethodGet, "/fonts/a.woff2", "")
	if w.Code != http.StatusOK || w.Body.String() != "font" || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("font: code=%d body=%q cache=%q", w.Code, w.Body.String(), w.Header().Get("Cache-Control"))
	}
	for _, path := range []string{"/fonts/", "/fonts/OFL.txt", "/fonts/missing.woff2", "/fonts/../main.go", "/fonts/sub/a.woff2"} {
		if w := doRequest(h, http.MethodGet, path, ""); w.Code == http.StatusOK {
			t.Errorf("%s: got 200, want not served", path)
		}
	}
}

func TestNormalFlow(t *testing.T) {
	h := newTestApp(t).h
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	code, resp := loadNote(t, h, hash)
	if code != http.StatusOK || resp.Content != "" || resp.Salt != "" {
		t.Fatalf("first load: code=%d content=%q salt=%q", code, resp.Content, resp.Salt)
	}

	if code := saveNote(t, h, hash, "hello world"); code != http.StatusOK {
		t.Fatalf("create: got %d", code)
	}

	code, resp = loadNote(t, h, hash)
	if code != http.StatusOK || resp.Content != "hello world" || resp.Salt != testSalt {
		t.Fatalf("second load: code=%d content=%q salt=%q", code, resp.Content, resp.Salt)
	}

	// An update may carry a different salt; the stored one must not change.
	if code := saveNoteAs(t, h, hash, "revision two", testToken, otherSalt); code != http.StatusOK {
		t.Fatalf("resave: got %d", code)
	}
	_, resp = loadNote(t, h, hash)
	if resp.Content != "revision two" || resp.Salt != testSalt {
		t.Fatalf("third load: content=%q salt=%q (want stable salt %q)", resp.Content, resp.Salt, testSalt)
	}
}

// --- Write token / no writes on load ---

func TestLoadNeverWrites(t *testing.T) {
	app := newTestApp(t)
	for _, c := range "0123456789abcdef" {
		if code, resp := loadNote(t, app.h, strings.Repeat(string(c), 32)); code != http.StatusOK || resp.Salt != "" {
			t.Fatalf("load of missing note: code=%d salt=%q", code, resp.Salt)
		}
	}
	if files := dataFiles(t, app.dir); len(files) != 0 {
		t.Fatalf("loads created files: %v", files)
	}
}

func TestSaveRequiresMatchingToken(t *testing.T) {
	app := newTestApp(t)
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if code := saveNote(t, app.h, hash, "owner's note"); code != http.StatusOK {
		t.Fatalf("create: got %d", code)
	}

	if code := saveNoteAs(t, app.h, hash, "vandalized", otherToken, otherSalt); code != http.StatusForbidden {
		t.Fatalf("wrong token: got %d, want 403", code)
	}
	if code := saveNoteAs(t, app.h, hash, "vandalized", "", testSalt); code != http.StatusBadRequest {
		t.Fatalf("missing token: got %d, want 400", code)
	}
	if _, resp := loadNote(t, app.h, hash); resp.Content != "owner's note" || resp.Salt != testSalt {
		t.Fatalf("rejected saves changed the note: content=%q salt=%q", resp.Content, resp.Salt)
	}
	if code := saveNote(t, app.h, hash, "owner edit"); code != http.StatusOK {
		t.Fatalf("owner update: got %d", code)
	}

	// The token itself never reaches disk, only its digest.
	raw, _ := base64.StdEncoding.DecodeString(testToken)
	stored, err := os.ReadFile(filepath.Join(app.dir, hash+authSuffix))
	if err != nil || string(stored) != tokenDigest(raw) {
		t.Fatalf("auth file = %q (%v), want digest", stored, err)
	}
}

func TestCreateValidatesSaltAndToken(t *testing.T) {
	app := newTestApp(t)
	hash := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	short := base64.StdEncoding.EncodeToString([]byte("short"))
	cases := []struct{ name, token, salt string }{
		{"no salt", testToken, ""},
		{"short salt", testToken, short},
		{"non-base64 salt", testToken, "!!!!"},
		{"short token", short, testSalt},
		{"non-base64 token", "!!!!", testSalt},
	}
	for _, c := range cases {
		if code := saveNoteAs(t, app.h, hash, "x", c.token, c.salt); code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", c.name, code)
		}
	}
	if files := dataFiles(t, app.dir); len(files) != 0 {
		t.Fatalf("rejected creates wrote files: %v", files)
	}
}

func TestNoteWithoutAuthIsNotWritable(t *testing.T) {
	// Content with no token digest (corruption / out-of-band file) must not be
	// claimable by whoever saves first.
	app := newTestApp(t)
	hash := "cccccccccccccccccccccccccccccccc"
	writeContentFile(t, app.dir, hash, "orphaned content")
	if code := saveNote(t, app.h, hash, "claimed"); code != http.StatusForbidden {
		t.Fatalf("save to note without auth: got %d, want 403", code)
	}
}

// --- Concurrency ---

func TestConcurrentCreates(t *testing.T) {
	// Many clients racing to create the same link with different tokens:
	// exactly one wins, and the note keeps the winner's salt.
	app := newTestApp(t)
	srv := httptest.NewServer(app.h)
	defer srv.Close()
	hash := "dddddddddddddddddddddddddddddddd"

	const n = 50
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			token := base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune('A'+i)), tokenBytes)))
			salt := base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune('A'+i)), saltBytes)))
			resp, err := srv.Client().Post(srv.URL+"/api/save", "application/json",
				strings.NewReader(savePayloadT(hash, "note", token, salt, "")))
			if err != nil {
				codes[i] = -1
				return
			}
			resp.Body.Close()
			codes[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	winners := 0
	for i, c := range codes {
		switch c {
		case http.StatusOK:
			winners++
		case http.StatusForbidden:
		default:
			t.Fatalf("create %d: got %d", i, c)
		}
	}
	if winners != 1 {
		t.Fatalf("%d creators won, want exactly 1", winners)
	}
}

func TestConcurrentLoads(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(app.h)
	defer srv.Close()
	hash := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	if code := saveNote(t, app.h, hash, "fixed content"); code != http.StatusOK {
		t.Fatalf("presave: got %d", code)
	}

	client := srv.Client()
	payload, _ := json.Marshal(map[string]string{"hash": hash})
	raw := string(payload)
	const n = 100
	var wg sync.WaitGroup
	contents := make([]string, n)
	salts := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := client.Post(srv.URL+"/api/load", "application/json", strings.NewReader(raw))
			if err != nil {
				contents[i] = "ERR"
				return
			}
			defer resp.Body.Close()
			var lr loadResp
			json.NewDecoder(resp.Body).Decode(&lr)
			contents[i] = lr.Content
			salts[i] = lr.Salt
		}(i)
	}
	wg.Wait()

	for i := range contents {
		if contents[i] != "fixed content" || salts[i] == "" || salts[i] != salts[0] {
			t.Fatalf("req %d: content=%q salt=%q", i, contents[i], salts[i])
		}
	}
}

func TestConcurrentSaves(t *testing.T) {
	// Many tabs saving concurrently from the same base version: exactly one
	// wins, the rest get 409, and the stored note is the winner's, untorn.
	app := newTestApp(t)
	srv := httptest.NewServer(app.h)
	defer srv.Close()
	hash := "ffffffffffffffffffffffffffffffff"
	if code := saveNote(t, app.h, hash, "base"); code != http.StatusOK {
		t.Fatalf("create: got %d", code)
	}
	_, cur := loadNote(t, app.h, hash)

	client := srv.Client()
	const n = 100
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload := savePayloadT(hash, strings.Repeat("x", i+1), testToken, testSalt, cur.Version)
			resp, err := client.Post(srv.URL+"/api/save", "application/json", strings.NewReader(payload))
			if err != nil {
				codes[i] = -1
				return
			}
			resp.Body.Close()
			codes[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	winner := -1
	for i, c := range codes {
		switch c {
		case http.StatusOK:
			if winner >= 0 {
				t.Fatalf("saves %d and %d both won from the same base", winner, i)
			}
			winner = i
		case http.StatusConflict:
		default:
			t.Fatalf("save %d: got %d", i, c)
		}
	}
	if winner < 0 {
		t.Fatal("no save won")
	}
	if _, resp := loadNote(t, app.h, hash); resp.Content != strings.Repeat("x", winner+1) {
		t.Fatalf("final content has %d bytes, want winner's %d", len(resp.Content), winner+1)
	}
}

func TestStaleBaseRejected(t *testing.T) {
	app := newTestApp(t)
	hash := "abababababababababababababababab"
	if code := saveNote(t, app.h, hash, "v1"); code != http.StatusOK {
		t.Fatalf("create: got %d", code)
	}
	_, tabA := loadNote(t, app.h, hash)
	_, tabB := loadNote(t, app.h, hash)

	if code := saveNoteBased(t, app.h, hash, "from A", testToken, testSalt, tabA.Version); code != http.StatusOK {
		t.Fatalf("tab A save: got %d", code)
	}
	if code := saveNoteBased(t, app.h, hash, "from B", testToken, testSalt, tabB.Version); code != http.StatusConflict {
		t.Fatalf("stale tab B save: got %d, want 409", code)
	}
	if code := saveNoteBased(t, app.h, hash, "no base", testToken, testSalt, ""); code != http.StatusConflict {
		t.Fatalf("save to existing note without base: got %d, want 409", code)
	}
	// A non-owner learns nothing from the version check: auth comes first.
	if code := saveNoteBased(t, app.h, hash, "x", otherToken, otherSalt, "stale"); code != http.StatusForbidden {
		t.Fatalf("wrong token with stale base: got %d, want 403", code)
	}
	_, now := loadNote(t, app.h, hash)
	if now.Content != "from A" {
		t.Fatalf("content = %q, want tab A's edit", now.Content)
	}

	// The save response carries the new version, so a tab can keep saving
	// without reloading.
	w := doRequest(app.h, http.MethodPost, "/api/save", savePayloadT(hash, "A again", testToken, testSalt, now.Version))
	var saved struct{ Version string }
	json.Unmarshal(w.Body.Bytes(), &saved)
	if w.Code != http.StatusOK || saved.Version == "" {
		t.Fatalf("save: code=%d version=%q", w.Code, saved.Version)
	}
	if code := saveNoteBased(t, app.h, hash, "A third", testToken, testSalt, saved.Version); code != http.StatusOK {
		t.Fatalf("save chained on returned version: got %d", code)
	}
}

func TestExpiredNoteRecreatedByOpenTab(t *testing.T) {
	// If cleanup removed the note while a tab was open, that tab's next save
	// (with its now-meaningless base) re-creates it instead of failing forever.
	app := newTestApp(t)
	hash := "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	saveNote(t, app.h, hash, "v1")
	_, tab := loadNote(t, app.h, hash)
	for _, suffix := range []string{contentSuffix, saltSuffix, authSuffix} {
		os.Remove(filepath.Join(app.dir, hash+suffix))
	}
	if code := saveNoteBased(t, app.h, hash, "still here", testToken, testSalt, tab.Version); code != http.StatusOK {
		t.Fatalf("save after expiry: got %d", code)
	}
}

// --- Failure cases ---

func TestInvalidHash(t *testing.T) {
	h := newTestApp(t).h
	bad := []string{
		"",
		"G",
		"A",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"aaaaaaaaaaaaaaaa",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
		" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	for _, hash := range bad {
		if code := saveNote(t, h, hash, "x"); code != http.StatusBadRequest {
			t.Errorf("save hash=%q: got %d, want 400", hash, code)
		}
		if code, _ := loadNote(t, h, hash); code != http.StatusBadRequest {
			t.Errorf("load hash=%q: got %d, want 400", hash, code)
		}
	}
}

func TestOversizedContent(t *testing.T) {
	app := newTestApp(t) // maxContentSizeMB = 1
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tooBig := strings.Repeat("a", int(maxContentBytes+1))
	if code := saveNote(t, app.h, hash, tooBig); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized save: got %d, want 413", code)
	}
	// Far past the limit the body reader itself trips; still 413, not 400.
	wayTooBig := strings.Repeat("a", int(maxRequestBytes*2))
	if code := saveNote(t, app.h, hash, wayTooBig); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("far oversized save: got %d, want 413", code)
	}
	// nothing persisted for a rejected save
	if _, err := os.Stat(filepath.Join(app.dir, hash+"_content.txt")); !os.IsNotExist(err) {
		t.Fatalf("rejected save still wrote a file: %v", err)
	}
}

func TestMalformedJSON(t *testing.T) {
	h := newTestApp(t).h
	for _, body := range []string{"", "not json", "[]", "{", "{]", `{"hash"}`} {
		w := doRequest(h, http.MethodPost, "/api/save", body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %q: got %d, want 400", body, w.Code)
		}
	}
}

func TestTrailingJSON(t *testing.T) {
	h := newTestApp(t).h
	for _, body := range []string{
		`{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}{"x":"y"}`,
		`{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}garbage`,
		`{"hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {"x":"y"}`,
	} {
		if code := doRequest(h, http.MethodPost, "/api/save", body).Code; code != http.StatusBadRequest {
			t.Errorf("trailing body %q: got %d, want 400", body, code)
		}
	}
}

func TestLongHashAccepted(t *testing.T) {
	app := newTestApp(t)
	id := strings.Repeat("f", 32)

	// Uppercase must still be rejected regardless of width.
	if code := saveNote(t, app.h, strings.ToUpper(id), "x"); code != http.StatusBadRequest {
		t.Fatalf("uppercase 32-hex: got %d, want 400", code)
	}
	if code := saveNote(t, app.h, id, "hello via long link"); code != http.StatusOK {
		t.Fatalf("save 32-hex: got %d", code)
	}
	if code, resp := loadNote(t, app.h, id); code != http.StatusOK || resp.Content != "hello via long link" {
		t.Fatalf("load 32-hex: code=%d content=%q", code, resp.Content)
	}
	// The old 16-hex password-derived width is no longer accepted.
	if code, _ := loadNote(t, app.h, "aaaaaaaaaaaaaaaa"); code != http.StatusBadRequest {
		t.Fatalf("16-hex load: got %d, want 400", code)
	}
}

func TestPermissionDenied(t *testing.T) {
	app := newTestApp(t)
	// A regular file in place of the data dir makes every write fail
	// deterministically, even when tests run as root.
	fakeDir := filepath.Join(app.dir, "not_a_dir")
	if err := os.WriteFile(fakeDir, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	dataDir = fakeDir

	if code := saveNote(t, app.h, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "hello"); code != http.StatusInternalServerError {
		t.Fatalf("save with broken data dir: got %d, want 500", code)
	}
	if code, _ := loadNote(t, app.h, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); code != http.StatusInternalServerError {
		t.Fatalf("load with broken data dir: got %d, want 500", code)
	}
}

// --- CORS ---

func TestCORS(t *testing.T) {
	app := newTestApp(t)
	corsOrigins = "https://allowed.example"

	// preflight for an allowed origin
	req := httptest.NewRequest(http.MethodOptions, "/api/save", nil)
	req.Header.Set("Origin", "https://allowed.example")
	w := httptest.NewRecorder()
	app.h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent ||
		w.Header().Get("Access-Control-Allow-Origin") != "https://allowed.example" {
		t.Fatalf("allowed preflight: code=%d ao=%q", w.Code, w.Header().Get("Access-Control-Allow-Origin"))
	}

	// denied origin must not proceed and must not echo the origin
	req = httptest.NewRequest(http.MethodPost, "/api/save", nil)
	req.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	app.h.ServeHTTP(w, req)
	if w.Code == http.StatusMethodNotAllowed && w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("denied origin: got through as %d with ACAO %q", w.Code, w.Header().Get("Access-Control-Allow-Origin"))
	}

	// wildcard when explicitly opted in
	corsOrigins = "*"
	req = httptest.NewRequest(http.MethodPost, "/api/save", nil)
	req.Header.Set("Origin", "https://anything.example")
	w = httptest.NewRecorder()
	app.h.ServeHTTP(w, req)
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("wildcard: ACAO = %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

// --- Cleanup ---

func TestCleanupByAge(t *testing.T) {
	app := newTestApp(t) // ageLimitDays = 2
	hashA, hashB, hashC := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccccccccc"
	old := time.Now().Add(-72 * time.Hour)

	for _, p := range []string{
		filepath.Join(app.dir, hashA+"_content.txt"),
		filepath.Join(app.dir, hashA+"_salt.txt"),
		filepath.Join(app.dir, hashA+"_auth.txt"),
		filepath.Join(app.dir, hashB+"_content.txt"),
		filepath.Join(app.dir, hashB+"_salt.txt"),
		filepath.Join(app.dir, hashB+"_auth.txt"),
	} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if code := saveNote(t, app.h, hashC, "fresh"); code != http.StatusOK {
		t.Fatalf("fresh save: got %d", code)
	}

	cleanupFiles()

	for _, p := range []string{
		filepath.Join(app.dir, hashA+"_content.txt"),
		filepath.Join(app.dir, hashA+"_salt.txt"),
		filepath.Join(app.dir, hashA+"_auth.txt"),
		filepath.Join(app.dir, hashB+"_content.txt"),
		filepath.Join(app.dir, hashB+"_salt.txt"),
		filepath.Join(app.dir, hashB+"_auth.txt"),
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("old file %s survived cleanup: %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(app.dir, hashC+"_content.txt")); err != nil {
		t.Errorf("fresh file was deleted: %v", err)
	}
}

func TestCleanupBySize(t *testing.T) {
	app := newTestApp(t)
	maxTotalSizeMB = 1 // cap at 1 MiB
	purgeToSizeMB = 1  // delete oldest until back under 1 MiB
	target := int64(purgeToSizeMB) * 1024 * 1024

	block := strings.Repeat("a", 400*1024)
	hashA, hashB, hashC := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccccccccc"
	pa := writeContentFile(t, app.dir, hashA, block)
	pb := writeContentFile(t, app.dir, hashB, block)
	pc0 := time.Now()
	os.Chtimes(pa, pc0.Add(-2*time.Hour), pc0.Add(-2*time.Hour))
	os.Chtimes(pb, pc0.Add(-1*time.Hour), pc0.Add(-1*time.Hour))
	pc := writeContentFile(t, app.dir, hashC, block)

	cleanupFiles()

	if _, err := os.Stat(pa); !os.IsNotExist(err) {
		t.Errorf("oldest file %s survived size purge", pa)
	}
	var kept int64
	for _, p := range []string{pb, pc} {
		if st, err := os.Stat(p); err != nil {
			t.Errorf("%s missing after purge: %v", p, err)
		} else {
			kept += st.Size()
		}
	}
	if kept > target {
		t.Errorf("kept %d bytes, want <= %d", kept, target)
	}
}

func TestLoadCountsAsActivity(t *testing.T) {
	// A note that is only read, never edited, must not expire while in use.
	app := newTestApp(t) // ageLimitDays = 2
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if code := saveNote(t, app.h, hash, "read-only note"); code != http.StatusOK {
		t.Fatalf("save: got %d", code)
	}
	contentPath := filepath.Join(app.dir, hash+contentSuffix)
	old := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(contentPath, old, old); err != nil {
		t.Fatal(err)
	}
	_, before := loadNote(t, app.h, hash)

	cleanupFiles()

	if _, err := os.Stat(contentPath); err != nil {
		t.Fatalf("recently opened note was deleted: %v", err)
	}
	// The activity mark must not look like an edit to other tabs.
	if _, after := loadNote(t, app.h, hash); after.Version != before.Version || after.Content != "read-only note" {
		t.Fatalf("load changed the note: version %q -> %q", before.Version, after.Version)
	}

	// Without any open, the same age still expires the note.
	if err := os.Chtimes(contentPath, old, old); err != nil {
		t.Fatal(err)
	}
	cleanupFiles()
	if _, err := os.Stat(contentPath); !os.IsNotExist(err) {
		t.Fatalf("unopened old note survived cleanup: %v", err)
	}
}

func TestCleanupSkipsFreshlySaved(t *testing.T) {
	// A note saved just before cleanup (same storageMu critical section) must
	// never be deleted: simulate by saving and immediately running cleanup.
	app := newTestApp(t)
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if code := saveNote(t, app.h, hash, "brand new"); code != http.StatusOK {
		t.Fatalf("save: got %d", code)
	}
	cleanupFiles()
	if _, err := os.Stat(filepath.Join(app.dir, hash+"_content.txt")); err != nil {
		t.Errorf("fresh note deleted: %v", err)
	}
}

// --- Write budget (H1: no unbounded disk growth between cleanups) ---

func TestWriteBudgetRejectsWhenFull(t *testing.T) {
	app := newTestApp(t)
	maxTotalSizeMB = 1 // cap at 1 MiB so the budget binds with 600 KiB notes

	big := strings.Repeat("a", 600*1024)
	if code := saveNote(t, app.h, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", big); code != http.StatusOK {
		t.Fatalf("first save: got %d", code)
	}

	// A second note would push total to 1.2 MiB > 1 MiB → rejected, file never
	// created.
	if code := saveNote(t, app.h, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", big); code != http.StatusInsufficientStorage {
		t.Fatalf("oversubscribed save: got %d, want 507", code)
	}
	if _, err := os.Stat(filepath.Join(app.dir, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb_content.txt")); !os.IsNotExist(err) {
		t.Fatalf("rejected save still wrote a file: %v", err)
	}

	// Shrinking an existing note is always allowed (net size decreases).
	if code := saveNote(t, app.h, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "tiny"); code != http.StatusOK {
		t.Fatalf("shrink save: got %d", code)
	}
	if usedBytes != int64(len("tiny")) {
		t.Fatalf("usedBytes = %d, want %d", usedBytes, len("tiny"))
	}

	// Cleanup reclaims headroom: after a purge the same big note is accepted.
	cleanupFiles()
	if code := saveNote(t, app.h, "cccccccccccccccccccccccccccccccc", big); code != http.StatusOK {
		t.Fatalf("post-cleanup save: got %d", code)
	}
}

func TestWriteBudgetTracksCleanup(t *testing.T) {
	app := newTestApp(t)
	// Write files directly (bypassing the budget) then clean up: usedBytes must
	// reflect what remains, not what was written before.
	writeContentFile(t, app.dir, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", strings.Repeat("a", 300*1024))
	cleanupFiles()
	if usedBytes != 300*1024 {
		t.Fatalf("usedBytes = %d after cleanup, want %d", usedBytes, 300*1024)
	}
}

// --- Orphan sidecar GC (crashed creates must not leak files) ---

func TestOrphanSaltsReclaimed(t *testing.T) {
	app := newTestApp(t)
	hashA, hashB := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	// A: content + sidecars → sidecars must survive.
	writeContentFile(t, app.dir, hashA, "live note")
	// B: sidecars only, no content (crashed create) → orphans, must be reclaimed.
	for _, hash := range []string{hashA, hashB} {
		for _, suffix := range sidecarSuffixes {
			if err := os.WriteFile(filepath.Join(app.dir, hash+suffix), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}

	cleanupFiles()

	if _, err := os.Stat(filepath.Join(app.dir, hashA+contentSuffix)); err != nil {
		t.Errorf("live content deleted: %v", err)
	}
	for _, suffix := range sidecarSuffixes {
		if _, err := os.Stat(filepath.Join(app.dir, hashA+suffix)); err != nil {
			t.Errorf("%s for a live note was deleted: %v", suffix, err)
		}
		if _, err := os.Stat(filepath.Join(app.dir, hashB+suffix)); !os.IsNotExist(err) {
			t.Errorf("orphan %s survived cleanup: %v", suffix, err)
		}
	}
}

func TestStaleTempFilesCleanup(t *testing.T) {
	app := newTestApp(t)
	stale := filepath.Join(app.dir, ".tmp-abandoned")
	if err := os.WriteFile(stale, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	cleanupFiles()
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale temp file survived cleanup: %v", err)
	}
}

// --- Atomicity / crash-safety primitives ---

func TestAtomicWriteBasics(t *testing.T) {
	app := newTestApp(t)
	path := filepath.Join(app.dir, "target.txt")

	if err := atomicWrite(path, "hello"); err != nil {
		t.Fatalf("atomicWrite: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "hello" {
		t.Fatalf("read back: %q, %v", got, err)
	}

	// overwrite in place
	if err := atomicWrite(path, "world"); err != nil {
		t.Fatalf("re-atomicWrite: %v", err)
	}
	got, _ = os.ReadFile(path)
	if string(got) != "world" {
		t.Fatalf("overwrite read back: %q", got)
	}

	// a failed write leaves nothing at the target it was aiming for
	dataDir = filepath.Join(app.dir, "missing_subdir")
	neverPath := filepath.Join(app.dir, "never.txt")
	if err := atomicWrite(neverPath, "x"); err == nil {
		t.Fatal("atomicWrite into missing dir should fail")
	}
	if _, err := os.Stat(neverPath); !os.IsNotExist(err) {
		t.Fatalf("failed write leaked a target file: %v", err)
	}
}

func TestAtomicWritePartialNeverVisible(t *testing.T) {
	app := newTestApp(t)
	path := filepath.Join(app.dir, "note.txt")
	if err := atomicWrite(path, strings.Repeat("z", 64*1024)); err != nil {
		t.Fatal(err)
	}
	// Read concurrently while another writer re-writes; readers must always
	// observe either the complete old content or the complete new content.
	const rounds = 20
	var wg sync.WaitGroup
	wg.Add(2)
	stop := make(chan struct{})
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			atomicWrite(path, strings.Repeat(string(rune('a'+i)), 64*1024))
		}
		close(stop)
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				got, err := os.ReadFile(path)
				if err != nil {
					t.Errorf("read failed: %v", err)
					return
				}
				if len(got) != 64*1024 {
					t.Errorf("read a torn file of %d bytes", len(got))
					return
				}
			}
		}
	}()
	wg.Wait()
}
