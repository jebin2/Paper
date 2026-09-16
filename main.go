package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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
	dataDir          = getenv("DATA_DIR", "/tmp")
	maxTotalSizeMB   = getenvInt("MAX_TOTAL_SIZE_MB", 100)
	purgeToSizeMB    = getenvInt("PURGE_TO_SIZE_MB", 80)
	ageLimitDays     = getenvInt("AGE_LIMIT_DAYS", 2)
	maxContentSizeMB = getenvInt("MAX_CONTENT_SIZE_MB", 10)
	cleanupInterval  = time.Duration(getenvInt("CLEANUP_INTERVAL_MINUTES", 15)) * time.Minute
	corsOrigins      = getenv("CORS_ORIGINS", "*")
	staticDir        = getenv("STATIC_DIR", "")
	listenAddr       = getenv("LISTEN_ADDR", "0.0.0.0")
	listenPort       = getenv("LISTEN_PORT", "7860")
	maxContentBytes  = int64(maxContentSizeMB) * 1024 * 1024
	maxRequestBytes  = maxContentBytes + 64*1024 // JSON envelope overhead on top of the content limit
)

var (
	hashRe    = regexp.MustCompile(`^[0-9a-f]{16}$`)
	storageMu sync.Mutex // serializes save + cleanup so cleanup never deletes a freshly-saved note
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

// ensureSalt returns the note's salt, creating it if it doesn't exist.
//
// Callers hold storageMu, so no other goroutine can create the salt between
// the existence check and the write — a plain check-then-create is safe.
// atomicWrite keeps the creation crash-safe: a reader never sees a
// partially-written salt.
func ensureSalt(saltPath string) (string, error) {
	if got, err := os.ReadFile(saltPath); err == nil {
		return string(got), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	saltBytes := make([]byte, 16)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", err
	}
	salt := base64.StdEncoding.EncodeToString(saltBytes)

	if err := atomicWrite(saltPath, salt); err != nil {
		return "", err
	}
	return salt, nil
}

// cleanupFiles removes files older than the age limit, and if total size still
// exceeds the cap, deletes the oldest remaining files until under the purge
// threshold. Guarded by storageMu so it can never race a save.
func cleanupFiles() {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		log.Printf("Cleanup: cannot open data dir: %v", err)
		return
	}

	storageMu.Lock()
	defer storageMu.Unlock()

	pattern := filepath.Join(dataDir, "*_content.txt")
	contentFiles, err := filepath.Glob(pattern)
	if err != nil || len(contentFiles) == 0 {
		return
	}

	now := time.Now()
	ageThreshold := now.Add(-time.Duration(ageLimitDays) * 24 * time.Hour)

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
	maxSize := int64(maxTotalSizeMB) * 1024 * 1024
	if keptSize > maxSize {
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
		saltPath := strings.TrimSuffix(fi.path, "_content.txt") + "_salt.txt"
		for _, p := range []string{fi.path, saltPath} {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				log.Printf("Cleanup: error removing %s: %v", p, err)
			}
		}
		log.Printf("Cleanup: deleted %s", fi.path)
	}
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

	contentPath := filepath.Join(dataDir, fileHash+"_content.txt")
	saltPath := filepath.Join(dataDir, fileHash+"_salt.txt")

	// Serialize with cleanup so a note's content and salt are read as a single
	// consistent snapshot — cleanup can't delete the files mid-read. The lock is
	// released before the response is written, so a large note doesn't stall
	// other requests during network transmission.
	storageMu.Lock()

	salt, err := ensureSalt(saltPath)
	if err != nil {
		storageMu.Unlock()
		log.Printf("ensureSalt(%s): %v", fileHash, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to load content from server"})
		return
	}

	content := ""
	got, err := os.ReadFile(contentPath)
	switch {
	case err == nil:
		content = string(got)
	case errors.Is(err, os.ErrNotExist):
		content = ""
	default:
		storageMu.Unlock()
		log.Printf("ReadFile(%s): %v", contentPath, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to load content from server"})
		return
	}
	storageMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{"content": content, "salt": salt})
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

	if int64(len(encryptedContent)) > maxContentBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge,
			map[string]string{"error": "Content too large. Maximum size is " + strconv.Itoa(maxContentSizeMB) + "MB"})
		return
	}

	contentPath := filepath.Join(dataDir, fileHash+"_content.txt")

	// Serialize with cleanup so cleanup can't delete a note that was just saved.
	// The lock is released once the bytes are on disk, before the response is
	// written back over the network.
	storageMu.Lock()
	err := atomicWrite(contentPath, encryptedContent)
	storageMu.Unlock()

	if err != nil {
		log.Printf("save(%s): %v", fileHash, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Save failed on server"})
		return
	}

	// Cleanup runs only from the background worker — never on the request path.
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

func main() {
	if err := validateConfig(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
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

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/load", loadHandler)
	mux.HandleFunc("/api/save", saveHandler)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !applyCORS(w, r) {
			return
		}
		mux.ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:              listenAddr + ":" + listenPort,
		Handler:           handler,
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
