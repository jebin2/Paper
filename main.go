package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// --- CONFIGURATION (Environment Variables with Defaults) ---
var (
	dataDir          = getenv("DATA_DIR", "/var/lib/paper")
	maxTotalSizeMB   = getenvInt("MAX_TOTAL_SIZE_MB", 100)
	purgeToSizeMB    = getenvInt("PURGE_TO_SIZE_MB", 80)
	ageLimitDays     = getenvInt("AGE_LIMIT_DAYS", 2)
	maxContentSizeMB = getenvInt("MAX_CONTENT_SIZE_MB", 10)
	cleanupInterval  = time.Duration(getenvInt("CLEANUP_INTERVAL_MINUTES", 15)) * time.Minute
	corsOrigins      = getenv("CORS_ORIGINS", "")
	staticDir        = getenv("STATIC_DIR", "")
	listenAddr       = getenv("LISTEN_ADDR", "0.0.0.0")
	listenPort       = getenv("LISTEN_PORT", "7860")
	maxContentBytes  = int64(maxContentSizeMB) * 1024 * 1024
	maxRequestBytes  = maxContentBytes + 64*1024 // JSON envelope overhead on top of the content limit
)

var (
	// Note IDs are random 128-bit capability links: exactly 32 lowercase hex chars.
	hashRe    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	storageMu sync.Mutex // serializes save + cleanup so cleanup never deletes a freshly-saved note

	// usedBytes is the current total size of stored content files, maintained
	// under storageMu. It is the write budget: saves that would push the store
	// past MAX_TOTAL_SIZE_MB are rejected instead of letting the disk grow
	// unbounded between background cleanups.
	usedBytes int64
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// validateConfig refuses misconfigured storage limits before the server starts.
func validateConfig() error {
	switch {
	case maxTotalSizeMB <= 0:
		return errors.New("MAX_TOTAL_SIZE_MB must be > 0")
	case purgeToSizeMB <= 0:
		return errors.New("PURGE_TO_SIZE_MB must be > 0")
	case purgeToSizeMB >= maxTotalSizeMB:
		return errors.New("PURGE_TO_SIZE_MB must be < MAX_TOTAL_SIZE_MB")
	case maxContentSizeMB <= 0:
		return errors.New("MAX_CONTENT_SIZE_MB must be > 0")
	case ageLimitDays < 0:
		return errors.New("AGE_LIMIT_DAYS must be >= 0")
	case cleanupInterval <= 0:
		return errors.New("CLEANUP_INTERVAL_MINUTES must be > 0")
	}
	return nil
}

// --- CORS ---
func applyCORS(w http.ResponseWriter, r *http.Request) bool {
	if corsOrigins == "" {
		return true
	}
	allowed := "*"
	if corsOrigins != "*" {
		origin := r.Header.Get("Origin")
		allowed = ""
		w.Header().Add("Vary", "Origin")
		for _, o := range strings.Split(corsOrigins, ",") {
			o = strings.TrimSpace(o)
			if o == origin {
				allowed = o
				break
			}
		}
		if allowed == "" {
			return false
		}
	}
	w.Header().Set("Access-Control-Allow-Origin", allowed)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return false
	}
	return true
}

// --- SECURITY ---
// applySecurityHeaders sets a strict set of browser security headers on every
// response. The frontend runs client-side crypto (PBKDF2/AES in JS), so an XSS
// here would expose the plaintext note and password; the CSP keeps any injected
// script from running. The app's JS lives in /app.js so script-src 'self' needs
// no 'unsafe-inline'. Fonts are self-hosted, so no third party ever learns who
// opened Paper.
func applySecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy",
		"default-src 'none'; "+
			"script-src 'self'; "+
			"style-src 'self' 'unsafe-inline'; "+
			"font-src 'self'; "+
			"connect-src 'self'; "+
			"img-src 'self' data:; "+
			"object-src 'none'; frame-src 'none'; frame-ancestors 'none'; "+
			"base-uri 'self'; form-action 'self'; upgrade-insecure-requests")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
}

func sanitizeHash(hash string) bool {
	return hashRe.MatchString(hash)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// --- FILE MANAGEMENT ---
type fileInfo struct {
	path  string
	size  int64
	mtime time.Time
}

// atomicWrite stages data in a temporary file in the same directory, fsyncs it,
// then renames over the target. On POSIX the rename is atomic, so a reader
// always sees either the old content or the new content — never a partial write.
func atomicWrite(path string, data string) error {
	tmp, err := os.CreateTemp(dataDir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		tmp.Close()
		if !committed {
			os.Remove(tmpName)
		}
	}()

	if _, err := tmp.WriteString(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	committed = true

	// fsync the directory so the rename itself is durable across a crash.
	if d, err := os.Open(dataDir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// Each note is three files. Content is written last on creation, so its
// existence is what makes a note exist; the salt and write-token digest are
// sidecars that cleanup reclaims if they are ever orphaned.
const (
	contentSuffix = "_content.txt"
	saltSuffix    = "_salt.txt"
	authSuffix    = "_auth.txt"
)

var sidecarSuffixes = []string{saltSuffix, authSuffix}

const (
	saltBytes  = 16 // client-chosen PBKDF2 salt
	tokenBytes = 32 // client-derived write token (never the encryption key)
)

func notePath(hash, suffix string) string {
	return filepath.Join(dataDir, hash+suffix)
}

// decodeFixed decodes standard base64 and requires exactly n bytes.
func decodeFixed(s string, n int) ([]byte, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	return b, err == nil && len(b) == n
}

// contentVersion identifies one stored revision of a note. Saves must name the
// version they were based on, so a stale tab can't silently overwrite newer
// edits made elsewhere. Hashing the ciphertext needs no extra state on disk.
func contentVersion(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:16])
}

// tokenDigest is what the server stores for a write token. The token itself is
// never written to disk, so a leaked data dir can't be used to overwrite notes.
func tokenDigest(token []byte) string {
	sum := sha256.Sum256(token)
	return hex.EncodeToString(sum[:])
}

// cleanupFiles removes files older than the age limit, and if total size still
// exceeds the cap, deletes the oldest remaining files until under the purge
// threshold. It also reclaims orphaned sidecar files (a salt or write-token
// digest whose note is gone is useless and would otherwise accumulate) and
// stale temp files abandoned by a crash. It refreshes usedBytes, the write
// budget consulted on every save. Guarded by storageMu so it can never race a
// save.
func cleanupFiles() {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Printf("Cleanup: cannot open data dir: %v", err)
		return
	}
	storageMu.Lock()
	defer storageMu.Unlock()
	cleanupFilesLocked()
}

// cleanupFilesLocked performs the cleanup work. The caller must hold storageMu.
func cleanupFilesLocked() {
	cleanupTempFilesLocked()

	now := time.Now()
	ageThreshold := now.Add(-time.Duration(ageLimitDays) * 24 * time.Hour)

	pattern := filepath.Join(dataDir, "*"+contentSuffix)
	contentFiles, err := filepath.Glob(pattern)
	if err != nil {
		// Data dir unreadable: we can't know the true size, so assume the worst
		// and block further saves rather than risk an unbounded disk.
		usedBytes = maxSizeBytes()
		return
	}

	var all []fileInfo
	for _, f := range contentFiles {
		st, err := os.Stat(f)
		if err != nil {
			continue
		}
		all = append(all, fileInfo{path: f, size: st.Size(), mtime: st.ModTime()})
	}

	// Stage 1: delete files older than the age limit
	var keep []fileInfo
	var del []fileInfo
	for _, fi := range all {
		if fi.mtime.Before(ageThreshold) {
			del = append(del, fi)
		} else {
			keep = append(keep, fi)
		}
	}

	// Stage 2: from the remaining pool, delete oldest until size is acceptable
	var keptSize int64
	for _, fi := range keep {
		keptSize += fi.size
	}
	if keptSize > maxSizeBytes() {
		sort.Slice(keep, func(i, j int) bool { return keep[i].mtime.Before(keep[j].mtime) })
		target := int64(purgeToSizeMB) * 1024 * 1024
		for keptSize > target && len(keep) > 0 {
			del = append(del, keep[0])
			keptSize -= keep[0].size
			keep = keep[1:]
		}
	}

	// Stage 3: delete
	for _, fi := range del {
		base := strings.TrimSuffix(fi.path, contentSuffix)
		for _, p := range []string{fi.path, base + saltSuffix, base + authSuffix} {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				log.Printf("Cleanup: error removing %s: %v", p, err)
			}
		}
		log.Printf("Cleanup: deleted %s", fi.path)
	}

	// Refresh the write budget: whatever content survived is the new total.
	usedBytes = 0
	for _, fi := range keep {
		usedBytes += fi.size
	}

	// Stage 4: reclaim orphaned sidecars (no matching content file). A salt or
	// token digest only exists to serve its note; without content it is pure
	// waste. The reverse is never done — a sidecar whose content still exists is
	// never removed, or that note becomes undecryptable or unwritable.
	for _, suffix := range sidecarSuffixes {
		files, err := filepath.Glob(filepath.Join(dataDir, "*"+suffix))
		if err != nil {
			continue
		}
		for _, f := range files {
			contentPath := strings.TrimSuffix(f, suffix) + contentSuffix
			if _, err := os.Stat(contentPath); os.IsNotExist(err) {
				if rmErr := os.Remove(f); rmErr != nil && !os.IsNotExist(rmErr) {
					log.Printf("Cleanup: error removing %s: %v", f, rmErr)
				}
			}
		}
	}
}

// cleanupTempFilesLocked removes stale temp files — staged atomicWrite targets
// that a crash left behind. The caller must hold storageMu.
func cleanupTempFilesLocked() {
	tmpFiles, _ := filepath.Glob(filepath.Join(dataDir, ".tmp-*"))
	stale := time.Now().Add(-time.Hour)
	for _, f := range tmpFiles {
		if st, err := os.Stat(f); err == nil && st.ModTime().Before(stale) {
			if rmErr := os.Remove(f); rmErr != nil && !os.IsNotExist(rmErr) {
				log.Printf("Cleanup: error removing %s: %v", f, rmErr)
			}
		}
	}
}

func maxSizeBytes() int64 {
	return int64(maxTotalSizeMB) * 1024 * 1024
}

func cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cleanupFiles()
		case <-ctx.Done():
			return
		}
	}
}

// --- HANDLERS ---
func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
}

// fontsHandler serves the self-hosted web fonts. Only plain .woff2 files are
// exposed (no directory listings, no subpaths), and they're immutable, so
// browsers may cache them for a year.
func fontsHandler(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/fonts/")
	if name == "" || strings.ContainsAny(name, "/\\") || !strings.HasSuffix(name, ".woff2") {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	http.ServeFile(w, r, filepath.Join(staticDir, "fonts", name))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request) (map[string]string, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)

	var body map[string]string
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return nil, false
	}
	// Reject anything after the single JSON value: a second object OR trailing
	// garbage. The only acceptable result is a clean EOF. A single decoder is
	// required — a second decoder would start behind the first one's read-ahead
	// buffer and always see EOF.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Only one JSON object is allowed"})
		return nil, false
	}
	return body, true
}

func loadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	body, ok := decodeJSONBody(w, r)
	if !ok {
		return
	}
	fileHash := body["hash"]
	if !sanitizeHash(fileHash) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid hash format"})
		return
	}

	// Loads never create or change files (only an existing note's mtime, as an
	// activity mark). Serialize with save/cleanup so content and salt are read
	// as one consistent snapshot; the lock is released before the response is
	// written, so a large note doesn't stall other requests.
	storageMu.Lock()
	content, err := os.ReadFile(notePath(fileHash, contentSuffix))
	if errors.Is(err, os.ErrNotExist) {
		storageMu.Unlock()
		// No note at this link yet: the client picks a salt and the note comes
		// into existence on its first save.
		writeJSON(w, http.StatusOK, map[string]string{"content": "", "salt": "", "version": ""})
		return
	}
	var salt []byte
	if err == nil {
		salt, err = os.ReadFile(notePath(fileHash, saltSuffix))
	}
	if err == nil {
		// Opening a note counts as activity: expiry and size purges go by the
		// content file's mtime, so a note that's read but never edited stays
		// alive. Done under storageMu so cleanup can't judge a stale mtime.
		// Only an existing note is touched — unknown links still create nothing.
		now := time.Now()
		if terr := os.Chtimes(notePath(fileHash, contentSuffix), now, now); terr != nil {
			log.Printf("load: could not refresh note activity: %v", terr)
		}
	}
	storageMu.Unlock()

	if err != nil {
		log.Printf("load note failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to load content from server"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"content": string(content),
		"salt":    string(salt),
		"version": contentVersion(content),
	})
}

func saveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	body, ok := decodeJSONBody(w, r)
	if !ok {
		return
	}
	fileHash := body["hash"]
	encryptedContent := body["content"]

	if !sanitizeHash(fileHash) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid hash format"})
		return
	}
	token, ok := decodeFixed(body["token"], tokenBytes)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid write token"})
		return
	}

	if int64(len(encryptedContent)) > maxContentBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge,
			map[string]string{"error": "Content too large. Maximum size is " + strconv.Itoa(maxContentSizeMB) + "MB"})
		return
	}

	contentPath := notePath(fileHash, contentSuffix)
	digest := tokenDigest(token)

	// storageMu is held across the auth, version and budget checks AND the
	// write, so cleanup can't delete a just-saved note, two creators can't both
	// claim a link, two tabs can't both pass the version check, and the used-bytes counter never disagrees with the filesystem. It is
	// released once the bytes are on disk, before the response goes out.
	storageMu.Lock()

	old, err := os.ReadFile(contentPath)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		storageMu.Unlock()
		log.Printf("save read failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Save failed on server"})
		return
	}

	var salt []byte
	if exists {
		// Overwriting requires the token derived from the note's passphrase:
		// holding the link alone lets you fetch ciphertext, not destroy it.
		stored, err := os.ReadFile(notePath(fileHash, authSuffix))
		if err != nil || subtle.ConstantTimeCompare(stored, []byte(digest)) != 1 {
			storageMu.Unlock()
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "Wrong passphrase for this note"})
			return
		}
		// Checked only after auth, and only for existing notes: if the note
		// expired while a tab was open, the save simply re-creates it.
		if body["base"] != contentVersion(old) {
			storageMu.Unlock()
			writeJSON(w, http.StatusConflict,
				map[string]string{"error": "This note was changed in another tab or device"})
			return
		}
	} else if salt, ok = decodeFixed(body["salt"], saltBytes); !ok {
		storageMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid salt"})
		return
	}

	// Existing content (if any) is already counted in usedBytes; replacing it
	// with a smaller blob must not be rejected as an oversize write.
	current := usedBytes - int64(len(old))
	if current < 0 {
		current = 0 // bookkeeping drifted (file removed out of band); don't compound it
	}
	if current+int64(len(encryptedContent)) > maxSizeBytes() {
		storageMu.Unlock()
		writeJSON(w, http.StatusInsufficientStorage,
			map[string]string{"error": "Server storage is full. Try again later."})
		return
	}

	err = nil
	if !exists {
		// Sidecars first, content last: a crash before the content write leaves
		// only orphans that cleanup reclaims, never a note without its salt.
		err = atomicWrite(notePath(fileHash, saltSuffix), base64.StdEncoding.EncodeToString(salt))
		if err == nil {
			err = atomicWrite(notePath(fileHash, authSuffix), digest)
		}
	}
	if err == nil {
		err = atomicWrite(contentPath, encryptedContent)
	}
	if err == nil {
		usedBytes = current + int64(len(encryptedContent))
	}
	storageMu.Unlock()

	if err != nil {
		log.Printf("save failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Save failed on server"})
		return
	}

	// Cleanup runs only from the background worker — never on the request path.
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "saved",
		"version": contentVersion([]byte(encryptedContent)),
	})
}

// newHandler builds the full route table wrapped in security headers and CORS.
func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(staticDir, "app.js"))
	})
	mux.HandleFunc("/fonts/", fontsHandler)
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/load", loadHandler)
	mux.HandleFunc("/api/save", saveHandler)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applySecurityHeaders(w)
		if !applyCORS(w, r) {
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func main() {
	if err := validateConfig(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		log.Fatalf("Cannot create data dir %s: %v", dataDir, err)
	}
	if staticDir == "" {
		staticDir = "."
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Run cleanup once at startup so stale files don't linger after a restart,
	// then hand off to the periodic worker.
	cleanupFiles()
	go cleanupLoop(ctx)

	srv := &http.Server{
		Addr:              listenAddr + ":" + listenPort,
		Handler:           newHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("Paper listening on http://%s (data dir: %s)", srv.Addr, dataDir)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("Shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Graceful shutdown failed: %v", err)
	}
	log.Printf("Stopped.")
}
