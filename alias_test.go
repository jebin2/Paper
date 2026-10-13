package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type nameResp struct {
	Name  string `json:"name"`
	Error string `json:"error"`
}

func setName(t *testing.T, h http.Handler, ref, name, token string) (int, nameResp) {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"hash": ref, "name": name, "token": token})
	w := doRequest(h, http.MethodPost, "/api/name", string(payload))
	var resp nameResp
	json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

func TestValidAlias(t *testing.T) {
	good := []string{"abc", "groceries", "work-notes", "a1b2c3", "x-9", strings.Repeat("g", 32)}
	bad := []string{"", "ab", "-lead", "trail-", "UPPER", "has space", "dots.no", "sla/sh",
		strings.Repeat("g", 33),
		strings.Repeat("a", 32), // 32 hex chars is a note ID, not a name
		strings.Repeat("f", 32)}
	for _, s := range good {
		if !validAlias(s) {
			t.Errorf("validAlias(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if validAlias(s) {
			t.Errorf("validAlias(%q) = true, want false", s)
		}
	}
}

func TestNameRoundTrip(t *testing.T) {
	app := newTestApp(t)
	id := strings.Repeat("a", 32)
	if code := saveNote(t, app.h, id, "shopping list"); code != http.StatusOK {
		t.Fatalf("create: got %d", code)
	}

	code, resp := setName(t, app.h, id, "groceries", testToken)
	if code != http.StatusOK || resp.Name != "groceries" {
		t.Fatalf("set name: code=%d resp=%+v", code, resp)
	}

	// The name reaches the same note, with the same salt and version.
	byID, byName := mustLoad(t, app.h, id), mustLoad(t, app.h, "groceries")
	if byName.Content != byID.Content || byName.Salt != byID.Salt || byName.Version != byID.Version {
		t.Fatalf("name and ID disagree:\n by id   %+v\n by name %+v", byID, byName)
	}
	if byName.Name != "groceries" || byID.Name != "groceries" {
		t.Fatalf("load should report the note's name: %q / %q", byID.Name, byName.Name)
	}

	// Saving through the name updates the same note.
	if code := saveNote(t, app.h, "groceries", "milk, lemons"); code != http.StatusOK {
		t.Fatalf("save via name: got %d", code)
	}
	if got := mustLoad(t, app.h, id).Content; got != "milk, lemons" {
		t.Fatalf("content via ID = %q, want the edit made through the name", got)
	}
}

// A guessed name must not hand out the note's unguessable link.
func TestNameNeverRevealsNoteID(t *testing.T) {
	app := newTestApp(t)
	id := strings.Repeat("b", 32)
	saveNote(t, app.h, id, "secret")
	setName(t, app.h, id, "guessable", testToken)

	payload, _ := json.Marshal(map[string]string{"hash": "guessable"})
	body := doRequest(app.h, http.MethodPost, "/api/load", string(payload)).Body.String()
	if strings.Contains(body, id) {
		t.Fatalf("load by name leaked the note ID: %s", body)
	}
}

func TestNameRequiresWriteToken(t *testing.T) {
	app := newTestApp(t)
	id := strings.Repeat("c", 32)
	saveNote(t, app.h, id, "mine")

	if code, _ := setName(t, app.h, id, "stolen", otherToken); code != http.StatusForbidden {
		t.Fatalf("name with wrong token: got %d, want 403", code)
	}
	if code, _ := setName(t, app.h, id, "stolen", ""); code != http.StatusBadRequest {
		t.Fatalf("name without token: got %d, want 400", code)
	}
	if _, err := os.Stat(aliasPath("stolen")); !os.IsNotExist(err) {
		t.Fatalf("rejected naming still wrote a file: %v", err)
	}
}

func TestNameTakenAndRename(t *testing.T) {
	app := newTestApp(t)
	first, second := strings.Repeat("d", 32), strings.Repeat("e", 32)
	saveNote(t, app.h, first, "first note")
	saveNoteAs(t, app.h, second, "second note", otherToken, otherSalt)

	if code, _ := setName(t, app.h, first, "shared", testToken); code != http.StatusOK {
		t.Fatalf("first claim: got %d", code)
	}
	if code, resp := setName(t, app.h, second, "shared", otherToken); code != http.StatusConflict {
		t.Fatalf("second claim: got %d (%s), want 409", code, resp.Error)
	}
	// Re-claiming your own name is a no-op, not a conflict.
	if code, _ := setName(t, app.h, first, "shared", testToken); code != http.StatusOK {
		t.Fatalf("re-claim own name: got %d", code)
	}

	// Renaming drops the old name entirely.
	if code, _ := setName(t, app.h, first, "renamed", testToken); code != http.StatusOK {
		t.Fatalf("rename: got %d", code)
	}
	if code, resp := loadNote(t, app.h, "shared"); code != http.StatusOK || resp.Salt != "" {
		t.Fatalf("old name still resolves: code=%d salt=%q", code, resp.Salt)
	}
	if got := mustLoad(t, app.h, "renamed").Content; got != "first note" {
		t.Fatalf("new name content = %q", got)
	}
	// ...and the freed name can be taken by the other note.
	if code, _ := setName(t, app.h, second, "shared", otherToken); code != http.StatusOK {
		t.Fatalf("claim freed name: got %d", code)
	}
	if got := mustLoad(t, app.h, "shared").Content; got != "second note" {
		t.Fatalf("freed name content = %q", got)
	}
}

func TestNameRemoval(t *testing.T) {
	app := newTestApp(t)
	id := strings.Repeat("a", 32)
	saveNote(t, app.h, id, "note")
	setName(t, app.h, id, "temporary", testToken)

	if code, resp := setName(t, app.h, id, "", testToken); code != http.StatusOK || resp.Name != "" {
		t.Fatalf("remove name: code=%d resp=%+v", code, resp)
	}
	if code, resp := loadNote(t, app.h, "temporary"); code != http.StatusOK || resp.Salt != "" {
		t.Fatalf("removed name still resolves: code=%d salt=%q", code, resp.Salt)
	}
	if got := mustLoad(t, app.h, id); got.Content != "note" || got.Name != "" {
		t.Fatalf("note after name removal: %+v", got)
	}
	if _, err := os.Stat(aliasPath("temporary")); !os.IsNotExist(err) {
		t.Fatalf("alias file survived removal: %v", err)
	}
}

func TestNameOnMissingNote(t *testing.T) {
	app := newTestApp(t)
	if code, _ := setName(t, app.h, strings.Repeat("f", 32), "ghost", testToken); code != http.StatusNotFound {
		t.Fatalf("naming a note that doesn't exist: got %d, want 404", code)
	}
	if code, _ := setName(t, app.h, "unknown-name", "ghost", testToken); code != http.StatusNotFound {
		t.Fatalf("naming through an unknown name: got %d, want 404", code)
	}
	if code, _ := setName(t, app.h, strings.Repeat("a", 32), "Bad Name", testToken); code != http.StatusBadRequest {
		t.Fatalf("invalid name: got %d, want 400", code)
	}
}

func TestNamesCleanedUpWithNote(t *testing.T) {
	app := newTestApp(t) // ageLimitDays = 2
	id := strings.Repeat("a", 32)
	saveNote(t, app.h, id, "expiring note")
	setName(t, app.h, id, "expiring", testToken)

	old := time.Now().Add(-72 * time.Hour)
	for _, suffix := range append([]string{contentSuffix}, sidecarSuffixes...) {
		p := filepath.Join(app.dir, id+suffix)
		if _, err := os.Stat(p); err == nil {
			os.Chtimes(p, old, old)
		}
	}
	cleanupFiles()

	if _, err := os.Stat(aliasPath("expiring")); !os.IsNotExist(err) {
		t.Fatalf("name outlived its note: %v", err)
	}
	if _, err := os.Stat(filepath.Join(app.dir, id+nameSuffix)); !os.IsNotExist(err) {
		t.Fatalf("name sidecar outlived its note: %v", err)
	}
	if aliasCount != 0 {
		t.Fatalf("aliasCount = %d after cleanup, want 0", aliasCount)
	}
}

func TestStaleAliasReclaimed(t *testing.T) {
	app := newTestApp(t)
	id := strings.Repeat("a", 32)
	saveNote(t, app.h, id, "note")
	setName(t, app.h, id, "current", testToken)

	// Left by an interrupted rename: an alias the note no longer claims.
	if err := os.WriteFile(aliasPath("abandoned"), []byte(id), 0o600); err != nil {
		t.Fatal(err)
	}
	// Points at a note that never existed.
	if err := os.WriteFile(aliasPath("dangling"), []byte(strings.Repeat("9", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	// Not a note ID at all.
	if err := os.WriteFile(aliasPath("corrupt"), []byte("nonsense"), 0o600); err != nil {
		t.Fatal(err)
	}

	cleanupFiles()

	for _, gone := range []string{"abandoned", "dangling", "corrupt"} {
		if _, err := os.Stat(aliasPath(gone)); !os.IsNotExist(err) {
			t.Errorf("stale alias %q survived cleanup", gone)
		}
	}
	if _, err := os.Stat(aliasPath("current")); err != nil {
		t.Errorf("live alias was deleted: %v", err)
	}
	if aliasCount != 1 {
		t.Fatalf("aliasCount = %d, want 1", aliasCount)
	}
}

func TestNameCapEnforced(t *testing.T) {
	app := newTestApp(t)
	id := strings.Repeat("a", 32)
	saveNote(t, app.h, id, "note")
	aliasCount = maxAliases

	if code, _ := setName(t, app.h, id, "one-more", testToken); code != http.StatusInsufficientStorage {
		t.Fatalf("name past the cap: got %d, want 507", code)
	}
	aliasCount = 0
	if code, _ := setName(t, app.h, id, "one-more", testToken); code != http.StatusOK {
		t.Fatalf("name under the cap: got %d", code)
	}
}

// A name is only reserved while its note lives. When the note expires, the
// next asker gets the name, without waiting for cleanup to sweep the alias.
func TestExpiredNoteFreesItsName(t *testing.T) {
	app := newTestApp(t)
	gone, taker := strings.Repeat("a", 32), strings.Repeat("b", 32)
	saveNote(t, app.h, gone, "old note")
	saveNoteAs(t, app.h, taker, "new note", otherToken, otherSalt)
	if code, _ := setName(t, app.h, gone, "shared", testToken); code != http.StatusOK {
		t.Fatalf("first claim: got %d", code)
	}

	// Expiry, as cleanup would do it, but before cleanup touches the alias.
	if err := os.Remove(filepath.Join(app.dir, gone+contentSuffix)); err != nil {
		t.Fatal(err)
	}

	if code, resp := setName(t, app.h, taker, "shared", otherToken); code != http.StatusOK {
		t.Fatalf("claiming a dead note's name: got %d (%s), want 200", code, resp.Error)
	}
	if got := mustLoad(t, app.h, "shared").Content; got != "new note" {
		t.Fatalf("name resolves to %q, want the note that claimed it", got)
	}
	// Reusing the alias file must not double-count it against the cap.
	if aliasCount != 1 {
		t.Fatalf("aliasCount = %d after reclaiming a name, want 1", aliasCount)
	}
}

func mustLoad(t *testing.T, h http.Handler, ref string) loadResp {
	t.Helper()
	code, resp := loadNote(t, h, ref)
	if code != http.StatusOK {
		t.Fatalf("load %q: got %d", ref, code)
	}
	return resp
}
