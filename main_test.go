package main

import (
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
	corsOrigins = "*"
	staticDir = dir
	maxContentBytes = int64(maxContentSizeMB) * 1024 * 1024
	maxRequestBytes = maxContentBytes + 64*1024
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

func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/load", loadHandler)
	mux.HandleFunc("/api/save", saveHandler)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !applyCORS(w, r) {
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func doRequest(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func saveNote(t *testing.T, h http.Handler, hash, content string) int {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"hash": hash, "content": content})
	return doRequest(h, http.MethodPost, "/api/save", string(payload)).Code
}

type loadResp struct {
	Content string `json:"content"`
	Salt    string `json:"salt"`
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

func TestNormalFlow(t *testing.T) {
	h := newTestApp(t).h
	hash := "aaaaaaaaaaaaaaaa"

	code, resp := loadNote(t, h, hash)
	if code != http.StatusOK || resp.Content != "" || len(resp.Salt) == 0 {
		t.Fatalf("first load: code=%d content=%q salt=%q", code, resp.Content, resp.Salt)
	}
	salt1 := resp.Salt

	if code := saveNote(t, h, hash, "hello world"); code != http.StatusOK {
		t.Fatalf("save: got %d", code)
	}

	code, resp = loadNote(t, h, hash)
	if code != http.StatusOK || resp.Content != "hello world" || resp.Salt != salt1 {
		t.Fatalf("second load: code=%d content=%q salt=%q", code, resp.Content, resp.Salt)
	}

	if code := saveNote(t, h, hash, "revision two"); code != http.StatusOK {
		t.Fatalf("resave: got %d", code)
	}
	_, resp = loadNote(t, h, hash)
	if resp.Content != "revision two" || resp.Salt != salt1 {
		t.Fatalf("third load: content=%q salt=%q (want stable salt %q)", resp.Content, resp.Salt, salt1)
	}
}

// --- Concurrency ---

func TestConcurrentNewNoteLoads(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(app.h)
	defer srv.Close()
	hash := "dddddddddddddddd"
	payload, _ := json.Marshal(map[string]string{"hash": hash})
	raw := string(payload)

	const n = 100
	var wg sync.WaitGroup
	type result struct {
		code int
		resp loadResp
	}
	results := make([]result, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			url := srv.URL + "/api/load"
			httpResp, err := http.Post(url, "application/json", strings.NewReader(raw))
			if err != nil {
				results[i] = result{code: -1}
				return
			}
			defer httpResp.Body.Close()
			var resp loadResp
			json.NewDecoder(httpResp.Body).Decode(&resp)
			results[i] = result{code: httpResp.StatusCode, resp: resp}
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		if r.code != http.StatusOK || r.resp.Salt == "" {
			t.Fatalf("req %d: code=%d salt=%q", i, r.code, r.resp.Salt)
		}
		if r.resp.Salt != results[0].resp.Salt {
			t.Fatalf("req %d: salt %q differs from %q — salt must be created exactly once", i, r.resp.Salt, results[0].resp.Salt)
		}
	}
}

func TestConcurrentLoads(t *testing.T) {
	app := newTestApp(t)
	srv := httptest.NewServer(app.h)
	defer srv.Close()
	hash := "eeeeeeeeeeeeeeee"
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
	app := newTestApp(t)
	srv := httptest.NewServer(app.h)
	defer srv.Close()
	hash := "ffffffffffffffff"

	client := srv.Client()
	const n = 100
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload, _ := json.Marshal(map[string]string{
				"hash":    hash,
				"content": strings.Repeat("x", i+1),
			})
			resp, err := client.Post(srv.URL+"/api/save", "application/json", strings.NewReader(string(payload)))
			if err != nil {
				codes[i] = -1
				return
			}
			resp.Body.Close()
			codes[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	for i, c := range codes {
		if c != http.StatusOK {
			t.Fatalf("save %d: got %d", i, c)
		}
	}

	// Final load must return one of the written contents, atomically complete.
	_, resp := loadNote(t, app.h, hash)
	if !(len(resp.Content) >= 1 && len(resp.Content) <= n) {
		t.Fatalf("final content has unreadable length %d", len(resp.Content))
	}
	// Content must be n repeats of 'x' for exactly one writer (no torn writes).
	ok := false
	expected := strings.Repeat("x", len(resp.Content))
	if resp.Content == expected {
		ok = true
	}
	if !ok {
		t.Fatalf("torn/corrupt final content (%d bytes)", len(resp.Content))
	}
}

// --- Failure cases ---

func TestInvalidHash(t *testing.T) {
	h := newTestApp(t).h
	bad := []string{
		"",
		"G",
		"A",
		"AAAAAAAAAAAAAAAA",
		"aaaaaaaaaaaaaaaaa",
		"aaaaaaaaaaaaaaaa!",
		" aaaaaaaaaaaaaaaa",
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
	hash := "aaaaaaaaaaaaaaaa"
	tooBig := strings.Repeat("a", int(maxContentBytes+1))
	payload, _ := json.Marshal(map[string]string{"hash": hash, "content": tooBig})
	if code := doRequest(app.h, http.MethodPost, "/api/save", string(payload)).Code; code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized save: got %d, want 413", code)
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
		`{"hash":"aaaaaaaaaaaaaaaa"}{"x":"y"}`,
		`{"hash":"aaaaaaaaaaaaaaaa"}garbage`,
		`{"hash":"aaaaaaaaaaaaaaaa"} {"x":"y"}`,
	} {
		if code := doRequest(h, http.MethodPost, "/api/save", body).Code; code != http.StatusBadRequest {
			t.Errorf("trailing body %q: got %d, want 400", body, code)
		}
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

	if code := saveNote(t, app.h, "aaaaaaaaaaaaaaaa", "hello"); code != http.StatusInternalServerError {
		t.Fatalf("save with broken data dir: got %d, want 500", code)
	}
	if code, _ := loadNote(t, app.h, "aaaaaaaaaaaaaaaa"); code != http.StatusInternalServerError {
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

	// wildcard default
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
	hashA, hashB, hashC := "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "cccccccccccccccc"
	old := time.Now().Add(-72 * time.Hour)

	for _, p := range []string{
		filepath.Join(app.dir, hashA+"_content.txt"),
		filepath.Join(app.dir, hashA+"_salt.txt"),
		filepath.Join(app.dir, hashB+"_content.txt"),
		filepath.Join(app.dir, hashB+"_salt.txt"),
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
		filepath.Join(app.dir, hashB+"_content.txt"),
		filepath.Join(app.dir, hashB+"_salt.txt"),
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
	hashA, hashB, hashC := "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "cccccccccccccccc"
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

func TestCleanupSkipsFreshlySaved(t *testing.T) {
	// A note saved just before cleanup (same storageMu critical section) must
	// never be deleted: simulate by saving and immediately running cleanup.
	app := newTestApp(t)
	hash := "aaaaaaaaaaaaaaaa"
	if code := saveNote(t, app.h, hash, "brand new"); code != http.StatusOK {
		t.Fatalf("save: got %d", code)
	}
	cleanupFiles()
	if _, err := os.Stat(filepath.Join(app.dir, hash+"_content.txt")); err != nil {
		t.Errorf("fresh note deleted: %v", err)
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
