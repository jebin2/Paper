package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// saveWithKDF creates a note that names the key derivation it was made with.
func saveWithKDF(t *testing.T, h http.Handler, hash, content, kdf string) int {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{
		"hash": hash, "content": content, "token": testToken, "salt": testSalt, "base": "", "kdf": kdf,
	})
	return doRequest(h, http.MethodPost, "/api/save", string(payload)).Code
}

func TestValidKDF(t *testing.T) {
	good := []string{"pbkdf2-sha256:100000", "pbkdf2-sha256:250000", "pbkdf2-sha256:600000",
		"pbkdf2-sha256:4000000"}
	bad := []string{"", "pbkdf2-sha256", "pbkdf2-sha256:", "pbkdf2-sha256:0",
		"pbkdf2-sha256:99999",   // under the floor
		"pbkdf2-sha256:4000001", // over the ceiling
		"pbkdf2-sha256:600000 ", // trailing space
		"PBKDF2-SHA256:600000",  // wrong case
		"argon2id:3",            // an algorithm this version can't run
		"pbkdf2-sha512:600000",
		"pbkdf2-sha256:6e5",
		"pbkdf2-sha256:-600000"}
	for _, s := range good {
		if !validKDF(s) {
			t.Errorf("validKDF(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if validKDF(s) {
			t.Errorf("validKDF(%q) = true, want false", s)
		}
	}
}

// The derivation is fixed when the note is created: changing it later would
// change the key and lock the owner out of their own note.
func TestKDFFixedAtCreation(t *testing.T) {
	app := newTestApp(t)
	id := strings.Repeat("a", 32)
	if code := saveWithKDF(t, app.h, id, "ciphertext", "pbkdf2-sha256:600000"); code != http.StatusOK {
		t.Fatalf("create: got %d", code)
	}
	if got := mustLoad(t, app.h, id).KDF; got != "pbkdf2-sha256:600000" {
		t.Fatalf("load reports kdf %q, want the one it was created with", got)
	}

	// A later save naming a different cost is ignored, not obeyed.
	payload, _ := json.Marshal(map[string]string{
		"hash": id, "content": "newer", "token": testToken, "salt": testSalt,
		"base": mustLoad(t, app.h, id).Version, "kdf": "pbkdf2-sha256:100000",
	})
	if code := doRequest(app.h, http.MethodPost, "/api/save", string(payload)).Code; code != http.StatusOK {
		t.Fatalf("overwrite: got %d", code)
	}
	if got := mustLoad(t, app.h, id).KDF; got != "pbkdf2-sha256:600000" {
		t.Fatalf("kdf changed under the note: %q", got)
	}
}

// Notes made before notes recorded this, and clients too old to send it, both
// used the legacy cost — reporting anything else would lock them out.
func TestKDFDefaultsToLegacy(t *testing.T) {
	app := newTestApp(t)

	noField := strings.Repeat("b", 32)
	if code := saveNote(t, app.h, noField, "ciphertext"); code != http.StatusOK {
		t.Fatalf("create without a kdf field: got %d", code)
	}
	if got := mustLoad(t, app.h, noField).KDF; got != legacyKDF {
		t.Fatalf("kdf for an old client = %q, want %q", got, legacyKDF)
	}

	// An existing note from before the sidecar existed.
	missing := strings.Repeat("c", 32)
	saveWithKDF(t, app.h, missing, "ciphertext", "pbkdf2-sha256:600000")
	if err := os.Remove(notePath(missing, kdfSuffix)); err != nil {
		t.Fatal(err)
	}
	if got := mustLoad(t, app.h, missing).KDF; got != legacyKDF {
		t.Fatalf("kdf with no sidecar = %q, want %q", got, legacyKDF)
	}

	// So is a sidecar that got corrupted.
	if err := os.WriteFile(notePath(missing, kdfSuffix), []byte("nonsense"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := mustLoad(t, app.h, missing).KDF; got != legacyKDF {
		t.Fatalf("kdf from a corrupt sidecar = %q, want %q", got, legacyKDF)
	}
}

func TestKDFRejectedWhenUnusable(t *testing.T) {
	app := newTestApp(t)
	for _, kdf := range []string{"argon2id:3", "pbkdf2-sha256:1", "pbkdf2-sha256:999999999", "garbage"} {
		id := strings.Repeat("d", 32)
		if code := saveWithKDF(t, app.h, id, "ciphertext", kdf); code != http.StatusBadRequest {
			t.Errorf("create with kdf %q: got %d, want 400", kdf, code)
		}
		if _, err := os.Stat(notePath(id, contentSuffix)); !os.IsNotExist(err) {
			t.Errorf("rejected kdf %q still created the note", kdf)
		}
	}
}

func TestKDFSidecarDeletedWithNote(t *testing.T) {
	app := newTestApp(t)
	id := strings.Repeat("e", 32)
	saveWithKDF(t, app.h, id, "ciphertext", "pbkdf2-sha256:600000")
	if _, err := os.Stat(notePath(id, kdfSuffix)); err != nil {
		t.Fatalf("kdf sidecar not written: %v", err)
	}
	if err := os.Remove(notePath(id, contentSuffix)); err != nil {
		t.Fatal(err)
	}
	cleanupFiles()
	if _, err := os.Stat(notePath(id, kdfSuffix)); !os.IsNotExist(err) {
		t.Fatalf("kdf sidecar outlived its note: %v", err)
	}
}
