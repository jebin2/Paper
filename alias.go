package main

import (
	"crypto/subtle"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// --- NAMES (custom links) ---
//
// A note always lives at its random 128-bit link. It may also be given one
// memorable name, so /#groceries reaches the same note as /#9f3c...
//
// The name is resolved on the server and the random link is never sent back,
// so guessing a name doesn't expose the strong link. A name IS guessable
// though: anyone who guesses it can download that note's ciphertext and attack
// the passphrase offline, with no rate limit in the way. Write tokens still
// keep them from changing the note.
//
// Files: <name>_alias.txt holds the note ID; <id>_name.txt holds the note's
// current name (so an editor can show it, and renames can drop the old name).

const (
	aliasSuffix = "_alias.txt"
	nameSuffix  = "_name.txt"

	// maxAliases bounds how many name files can accumulate. Each is tiny, but
	// nothing else caps their number.
	maxAliases = 10_000
)

// 3-32 chars: lowercase letters, digits and dashes, not starting or ending
// with a dash. A 32-hex string is a note ID, never a name.
var aliasRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`)

// aliasCount tracks stored names, maintained under storageMu and refreshed by
// cleanup, the same way usedBytes tracks content.
var aliasCount int

func validAlias(name string) bool {
	return aliasRe.MatchString(name) && !hashRe.MatchString(name)
}

// validRef reports whether s can address a note: an ID or a name.
func validRef(s string) bool {
	return hashRe.MatchString(s) || validAlias(s)
}

func aliasPath(name string) string {
	return filepath.Join(dataDir, name+aliasSuffix)
}

// resolveRef maps an ID or a name to a note ID. found is false when a
// well-formed name has no note behind it. Callers must hold storageMu.
func resolveRef(ref string) (id string, found bool, err error) {
	if hashRe.MatchString(ref) {
		return ref, true, nil
	}
	target, err := os.ReadFile(aliasPath(ref))
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	id = strings.TrimSpace(string(target))
	if !hashRe.MatchString(id) {
		return "", false, nil // corrupt pointer: treat as missing, cleanup will drop it
	}
	return id, true, nil
}

// noteName returns the note's current name, or "" if it has none.
// Callers must hold storageMu.
func noteName(id string) string {
	got, err := os.ReadFile(notePath(id, nameSuffix))
	if err != nil {
		return ""
	}
	name := strings.TrimSpace(string(got))
	if !validAlias(name) {
		return ""
	}
	return name
}

// setNoteName points name at id and makes it the note's only name, dropping
// whatever name it had before. Callers must hold storageMu.
func setNoteName(id, name string) error {
	previous := noteName(id)
	if previous == name {
		return nil
	}
	if err := atomicWrite(aliasPath(name), id); err != nil {
		return err
	}
	if err := atomicWrite(notePath(id, nameSuffix), name); err != nil {
		return err
	}
	aliasCount++
	if previous != "" {
		if err := os.Remove(aliasPath(previous)); err == nil {
			aliasCount--
		}
	}
	return nil
}

// clearNoteName removes a note's name, if it has one. Callers must hold storageMu.
func clearNoteName(id string) error {
	previous := noteName(id)
	if previous == "" {
		return nil
	}
	if err := os.Remove(aliasPath(previous)); err != nil && !os.IsNotExist(err) {
		return err
	}
	aliasCount--
	if err := os.Remove(notePath(id, nameSuffix)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// cleanupAliasesLocked drops names whose note is gone, and names the note no
// longer claims (left by an interrupted rename). It refreshes aliasCount.
// Callers must hold storageMu.
func cleanupAliasesLocked() {
	files, err := filepath.Glob(filepath.Join(dataDir, "*"+aliasSuffix))
	if err != nil {
		return
	}
	aliasCount = 0
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), aliasSuffix)
		target, readErr := os.ReadFile(f)
		id := strings.TrimSpace(string(target))

		stale := readErr != nil || !hashRe.MatchString(id)
		if !stale {
			if _, statErr := os.Stat(notePath(id, contentSuffix)); os.IsNotExist(statErr) {
				stale = true
			} else if noteName(id) != name {
				stale = true
			}
		}
		if stale {
			if rmErr := os.Remove(f); rmErr != nil && !os.IsNotExist(rmErr) {
				log.Printf("Cleanup: error removing %s: %v", f, rmErr)
			}
			continue
		}
		aliasCount++
	}
}

// emptyNote is the answer for a link or name with no note behind it.
var emptyNote = map[string]string{"content": "", "salt": "", "version": "", "name": ""}

// nameHandler gives a note its memorable name, renames it, or (with an empty
// name) removes it. Only the note's owner can: it takes the same write token
// as saving, so holding the link alone isn't enough.
func nameHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}
	body, ok := decodeJSONBody(w, r)
	if !ok {
		return
	}

	ref := body["hash"]
	name := strings.ToLower(strings.TrimSpace(body["name"]))
	if !validRef(ref) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid link"})
		return
	}
	if name != "" && !validAlias(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Names are 3-32 characters: lowercase letters, numbers and dashes"})
		return
	}
	token, ok := decodeFixed(body["token"], tokenBytes)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid write token"})
		return
	}

	storageMu.Lock()
	defer storageMu.Unlock()

	id, found, err := resolveRef(ref)
	if err != nil {
		log.Printf("name resolve failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Could not set the name"})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "This note doesn't exist yet"})
		return
	}
	if _, err := os.Stat(notePath(id, contentSuffix)); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "This note doesn't exist yet"})
		return
	}

	// Same proof as a save: only whoever knows the passphrase can name a note.
	stored, err := os.ReadFile(notePath(id, authSuffix))
	if err != nil || subtle.ConstantTimeCompare(stored, []byte(tokenDigest(token))) != 1 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Wrong passphrase for this note"})
		return
	}

	if name == "" {
		if err := clearNoteName(id); err != nil {
			log.Printf("clear name failed: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Could not remove the name"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"name": ""})
		return
	}

	switch target, taken, err := resolveRef(name); {
	case err != nil:
		log.Printf("name lookup failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Could not set the name"})
		return
	case taken && target != id:
		writeJSON(w, http.StatusConflict, map[string]string{"error": "That name is already taken"})
		return
	case !taken && aliasCount >= maxAliases:
		writeJSON(w, http.StatusInsufficientStorage, map[string]string{"error": "Too many names in use. Try again later."})
		return
	}

	if err := setNoteName(id, name); err != nil {
		log.Printf("set name failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Could not set the name"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": name})
}
