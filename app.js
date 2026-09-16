
        let currentKey = null;       // AES-GCM key, non-extractable; the passphrase itself isn't kept
        let currentToken = '';       // base64 write token proving knowledge of the passphrase
        let currentSalt = null;
        let currentVersion = '';     // server version this editor is based on ('' = note not created yet)
        let conflict = false;        // a save hit 409; autosave pauses until the user resolves it
        let fileHash = '';
        let saveTimeout = null;
        let retryAttempt = -1;       // index into SAVE_RETRY_BACKOFF (-1 = not retrying)
        let isWorking = false;       // login-in-progress guard only
        let isSaving = false;        // save-in-flight guard
        let dirty = false;           // unsaved edits exist
        let sessionActive = false;   // true once login succeeds, false on logout

        const PBKDF2_ITERATIONS = 250000;

        // After a failed save, retry with exponential-ish backoff so a
        // sustained outage doesn't turn into a busy retry loop. The ladder
        // resets to the start on any successful save (and on login/logout).
        const SAVE_RETRY_BACKOFF = [2000, 5000, 10000, 30000, 60000];

        // --- CARD FLIP ---
        // The hidden face is made inert so keyboard users can't tab into it.
        function flipCard() {
            const flipped = document.getElementById('cardContainer').classList.toggle('flipped');
            document.getElementById('cardFront').inert = flipped;
            document.getElementById('cardBack').inert = !flipped;
            document.getElementById(flipped ? 'backIcon' : 'infoIcon').focus();
        }

        // --- WORD COUNT ---
        function updateWordCount() {
            const text = document.getElementById('editor').value;
            const words = text.trim() ? text.trim().split(/\s+/).length : 0;
            const chars = text.length;
            const counter = document.getElementById('wordCount');
            counter.querySelector('.wc-words').textContent = `${words} ${words === 1 ? 'word' : 'words'}`;
            counter.querySelector('.wc-chars').textContent = `, ${chars} chars`;
        }

        // --- LOGIN SCREEN MODE ---
        // A link born in this session is a new note: any passphrase creates it,
        // and the link must be saved now or the note is unreachable. A link that
        // came in via the URL is an existing note to unlock.
        function renderLoginMode() {
            const badge = document.getElementById('modeBadge');
            badge.textContent = freshNote ? 'New note' : 'Existing note';
            badge.classList.toggle('new', freshNote);
            document.getElementById('loginSubtitle').textContent = freshNote
                ? 'Choose a passphrase to encrypt it. Notes vanish after 2 days without being opened or edited.'
                : 'Enter the passphrase for the note at this link.';
            document.getElementById('linkBox').hidden = !freshNote;
            document.getElementById('linkField').value = location.href;
            document.getElementById('strength').hidden = !freshNote;
            document.getElementById('newNoteLink').hidden = freshNote;
            document.getElementById('enterBtn').textContent = freshNote ? 'Create note' : 'Unlock';
            const input = document.getElementById('passwordInput');
            input.autocomplete = freshNote ? 'new-password' : 'current-password';
            input.placeholder = freshNote ? 'choose a passphrase' : 'passphrase';
            updateStrength();
        }

        // Length is the only thing measured, so the labels only talk about length.
        function updateStrength() {
            const len = document.getElementById('passwordInput').value.length;
            const meter = document.getElementById('strength');
            let level = '', label = '';
            if (len === 0) { level = ''; label = '16+ characters recommended'; }
            else if (len < 8) { level = 'weak'; label = `Too short (${len}/8)`; }
            else if (len < 16) { level = 'ok'; label = `Long enough — 16+ is better (${len})`; }
            else { level = 'strong'; label = 'Good length'; }
            meter.dataset.level = level;
            document.getElementById('strengthText').textContent = label;
        }

        function showScreen(editing) {
            document.getElementById('loginScreen').style.display = editing ? 'none' : 'flex';
            document.getElementById('editorScreen').style.display = editing ? 'flex' : 'none';
            document.body.classList.toggle('editing', editing);
        }

        // --- NOTE IDENTIFICATION ---
        // A note is identified by a random 128-bit capability in the URL, NOT
        // by the password. Possession of the link lets you reach the note; your
        // password is only used to derive the encryption key (via PBKDF2).
        const NOTE_ID_RE = /^[0-9a-f]{32}$/;

        function noteIdFromUrl() {
            const h = (location.hash || '').slice(1).toLowerCase();
            return NOTE_ID_RE.test(h) ? h : '';
        }

        function randomNoteId() {
            const bytes = new Uint8Array(16);
            crypto.getRandomValues(bytes);
            return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
        }

        // --- CRYPTOGRAPHY ---

        // Chunked conversion helpers that avoid the call-stack limit on
        // 10 MB payloads.  `String.fromCharCode.apply()` blows the stack
        // when the array is > ~65 k elements; 8 KB chunks stay safe.
        function toBase64(bytes) {
            const CHUNK = 8192;
            const chunks = [];
            for (let i = 0; i < bytes.length; i += CHUNK) {
                chunks.push(String.fromCharCode(...bytes.subarray(i, Math.min(i + CHUNK, bytes.length))));
            }
            return btoa(chunks.join(''));
        }

        function base64ToUint8Array(base64) {
            const bin = atob(base64);
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) {
                bytes[i] = bin.charCodeAt(i);
            }
            return bytes;
        }

        function randomSalt() {
            return crypto.getRandomValues(new Uint8Array(16));
        }

        // One PBKDF2 run yields 512 bits: the first half is the AES-256-GCM key,
        // the second half is the write token the server checks before letting a
        // save overwrite the note. The halves are independent, so the token
        // (which the server sees) reveals nothing about the key.
        async function deriveSecrets(password, salt) {
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(password),
                { name: 'PBKDF2' },
                false,
                ['deriveBits']
            );
            const bits = new Uint8Array(await crypto.subtle.deriveBits(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: PBKDF2_ITERATIONS,
                    hash: 'SHA-256'
                },
                keyMaterial,
                512
            ));
            const key = await crypto.subtle.importKey(
                'raw',
                bits.subarray(0, 32),
                { name: 'AES-GCM' },
                false,
                ['encrypt', 'decrypt']
            );
            return { key, token: toBase64(bits.subarray(32)) };
        }

        async function encrypt(text, key) {
            const encoder = new TextEncoder();
            const data = encoder.encode(text);
            const iv = crypto.getRandomValues(new Uint8Array(12));

            const encryptedContent = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                data
            );

            const combined = new Uint8Array(iv.length + encryptedContent.byteLength);
            combined.set(iv);
            combined.set(new Uint8Array(encryptedContent), iv.length);

            return toBase64(combined);
        }

        async function decrypt(encryptedBase64, key) {
            try {
                const combined = base64ToUint8Array(encryptedBase64);
                const iv = combined.slice(0, 12);
                const encryptedContent = combined.slice(12);

                const decrypted = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: iv },
                    key,
                    encryptedContent
                );

                return new TextDecoder().decode(decrypted);
            } catch (error) {
                console.error('Decryption failed:', error);
                throw new Error('Decryption failed. Check password.');
            }
        }

        // --- APPLICATION LOGIC ---
        document.getElementById('passwordInput').focus();
        document.getElementById('passwordInput').addEventListener('keypress', e => {
            if (e.key === 'Enter') login();
        });
        document.getElementById('passwordInput').addEventListener('input', updateStrength);

        // Migrated from inline onclick — enables strict CSP without 'unsafe-inline'
        document.getElementById('infoIcon').addEventListener('click', flipCard);
        document.getElementById('backIcon').addEventListener('click', flipCard);
        document.getElementById('cardContainer').addEventListener('keydown', e => {
            if (e.key === 'Escape' && document.getElementById('cardContainer').classList.contains('flipped')) flipCard();
        });
        document.getElementById('enterBtn').addEventListener('click', login);
        document.getElementById('newNoteLink').addEventListener('click', newNote);
        document.getElementById('lockBtn').addEventListener('click', lockNote);

        // Every note lives at a random link. A visitor landing without one gets
        // a freshly-generated capability; returning visitors keep theirs.
        let noteId = noteIdFromUrl();
        let freshNote = false;
        if (!noteId) {
            noteId = randomNoteId();
            freshNote = true;
        }
        fileHash = noteId; // lowercase hex from both sources
        history.replaceState(null, '', '#' + fileHash);
        renderLoginMode();
        document.getElementById('copyLinkBtn').addEventListener('click', e => copyLink(e.currentTarget));
        document.getElementById('loginCopyBtn').addEventListener('click', e => copyLink(e.currentTarget));
        document.getElementById('linkField').addEventListener('focus', e => e.target.select());

        // Autosave: the editor listener is registered exactly once, here —
        // not per-login — so repeat logins can't stack duplicate handlers.
        document.getElementById('editor').addEventListener('input', () => {
            if (!sessionActive) return;
            dirty = true;
            clearTimeout(saveTimeout);
            updateWordCount();
            if (conflict) return; // keep the conflict visible; saving waits for a choice
            // While saves are failing, keep the error visible instead of
            // masking it with a neutral "Editing" state.
            if (retryAttempt < 0) updateSaveStatus('Unsaved', 'pending');

            saveTimeout = setTimeout(saveIfDirty, 1500);
        });

        async function apiLoad(id) {
            const response = await fetch('/api/load', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ hash: id })
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || 'Load failed');
            return data;
        }

        // The salt only matters on the save that creates the note; the server
        // ignores it afterwards and keeps the original.
        // `base` is the version the edit started from; the server answers 409 if
        // the note has moved on since (another tab or device saved first).
        async function apiSave(id, content, token, salt, base) {
            const response = await fetch('/api/save', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ hash: id, content, token, salt: toBase64(salt), base })
            });
            const data = await response.json();
            if (!response.ok) {
                const err = new Error(data.error || 'Save failed');
                err.status = response.status;
                throw err;
            }
            return data;
        }

        async function login() {
            if (isWorking) return;
            isWorking = true;

            const password = document.getElementById('passwordInput').value;
            const errorDiv = document.getElementById('loginError');
            const enterBtn = document.querySelector('.enter-btn');

            errorDiv.textContent = '';
            if (password.length < 8) {
                errorDiv.textContent = 'Password must be at least 8 characters';
                isWorking = false;
                return;
            }

            enterBtn.textContent = freshNote ? 'Creating...' : 'Unlocking...';
            enterBtn.disabled = true;

            try {
                let content = '';

                // Loading never creates anything server-side. A link with no note
                // behind it gets a salt chosen here; the note (salt + write token)
                // comes into existence on its first save.
                const data = await apiLoad(fileHash);
                const salt = data.salt ? base64ToUint8Array(data.salt) : randomSalt();
                const { key, token } = await deriveSecrets(password, salt);
                if (data.content) {
                    content = await decrypt(data.content, key);
                }
                currentSalt = salt;
                currentKey = key;
                currentToken = token;
                currentVersion = data.version;
                setConflict(false);
                freshNote = false;

                const editor = document.getElementById('editor');
                editor.value = content;
                showScreen(true);
                sessionActive = true;
                dirty = false;
                isSaving = false;
                retryAttempt = -1;
                updateSaveStatus('Ready');
                updateWordCount();
                editor.focus();

            } catch (error) {
                errorDiv.textContent = error.message.includes('Decryption')
                    ? 'Wrong passphrase for this note'
                    : "Couldn't reach the server — check your connection";
            } finally {
                isWorking = false;
                renderLoginMode();
                enterBtn.disabled = false;
            }
        }

        async function saveIfDirty() {
            if (isSaving || !dirty || !sessionActive || conflict) return;
            dirty = false;
            isSaving = true;

            if (retryAttempt < 0) updateSaveStatus('Saving...', 'saving');

            const content = document.getElementById('editor').value;
            let failed = false;

            let rejected = false;

            try {
                const encryptedContent = await encrypt(content, currentKey);

                const saved = await apiSave(fileHash, encryptedContent, currentToken, currentSalt, currentVersion);
                currentVersion = saved.version;
                retryAttempt = -1;
                updateSaveStatus(dirty ? 'Unsaved' : 'Saved', dirty ? 'pending' : 'saved');
            } catch (error) {
                console.error('Save failed:', error);
                dirty = true;
                failed = true;
                // 403: the note at this link belongs to a different passphrase
                // (e.g. someone else created it first). Retrying can't fix that.
                rejected = error.status === 403;
                if (error.status === 409) setConflict(true);
            } finally {
                isSaving = false;

                // Delayed retry with backoff instead of an immediate
                // loop. A user typing will also schedule saves via the
                // debounce, but a quiet, failing session backs off
                // 2s -> 5s -> 10s -> 30s -> 60s.
                if (conflict) {
                    retryAttempt = -1;
                    updateSaveStatus('Not saved', 'error', ' · changed elsewhere');
                } else if (rejected) {
                    retryAttempt = -1;
                    updateSaveStatus('Not saved', 'error', ' · wrong passphrase for this note');
                } else if (dirty && sessionActive) {
                    const delay = failed
                        ? SAVE_RETRY_BACKOFF[retryAttempt = Math.min(retryAttempt + 1, SAVE_RETRY_BACKOFF.length - 1)]
                        : 1500; // edits arrived mid-save: normal debounce
                    if (failed) updateSaveStatus('Not saved', 'error', ` · retrying in ${delay / 1000}s`);
                    clearTimeout(saveTimeout);
                    saveTimeout = setTimeout(saveIfDirty, delay);
                }
            }
        }

        function copyLink(btn) {
            const label = btn.textContent;
            navigator.clipboard.writeText(location.href).then(() => {
                btn.textContent = 'Copied!';
                setTimeout(() => { btn.textContent = label; }, 1500);
            }).catch(() => {
                // Clipboard blocked (e.g. insecure context): fall back to selecting the link
                const field = document.getElementById('linkField');
                if (!field.closest('[hidden]')) field.select();
            });
        }

        function newNote() {
            const id = randomNoteId();
            history.replaceState(null, '', '#' + id);
            fileHash = id;
            freshNote = true;
            currentKey = null;
            currentToken = '';
            currentSalt = null;
            currentVersion = '';
            setConflict(false);
            sessionActive = false;
            dirty = false;
            retryAttempt = -1;
            clearTimeout(saveTimeout);
            document.getElementById('passwordInput').value = '';
            document.getElementById('editor').value = '';
            document.getElementById('loginError').textContent = '';
            renderLoginMode();
            showScreen(false);
            document.getElementById('passwordInput').focus();
        }

        // Locking with pending edits first tries to save them right away; the
        // user is only asked when that isn't possible (offline, conflict, ...).
        async function lockNote() {
            if (!sessionActive) return;
            const lockBtn = document.getElementById('lockBtn');
            lockBtn.disabled = true;
            try {
                if (!conflict && (dirty || isSaving)) {
                    clearTimeout(saveTimeout);
                    while (isSaving) await new Promise(r => setTimeout(r, 100));
                    if (dirty && !conflict) await saveIfDirty();
                }
                if ((dirty || isSaving) && !(await confirmLock())) return;
                goToLogin();
            } finally {
                lockBtn.disabled = false;
            }
        }

        function confirmLock() {
            const dialog = document.getElementById('lockDialog');
            document.getElementById('lockDialogText').textContent = conflict
                ? 'This note was changed elsewhere and your edits here aren\'t saved. If you lock now, they\'ll be lost.'
                : 'Your latest edits couldn\'t be saved. If you lock now, they\'ll be lost.';
            return new Promise(resolve => {
                dialog.returnValue = 'cancel';
                dialog.addEventListener('close', () => resolve(dialog.returnValue === 'lock'), { once: true });
                dialog.showModal();
            });
        }

        function goToLogin() {
            // Clear sensitive data — the note link itself stays in the URL, so
            // logging out reopens the same note.
            currentKey = null;
            currentToken = '';
            currentSalt = null;
            currentVersion = '';
            setConflict(false);
            fileHash = noteIdFromUrl();
            clearTimeout(saveTimeout);
            sessionActive = false;
            dirty = false;
            retryAttempt = -1;

            // Reset UI
            document.getElementById('editor').value = '';
            document.getElementById('passwordInput').value = '';
            document.getElementById('loginError').textContent = '';
            renderLoginMode();
            showScreen(false);
            document.getElementById('passwordInput').focus();
        }

        // --- CONFLICTS (another tab or device saved first) ---
        function setConflict(on) {
            conflict = on;
            document.getElementById('conflictBar').hidden = !on;
        }

        async function fetchLatest() {
            const data = await apiLoad(fileHash);
            return {
                version: data.version,
                content: data.content ? await decrypt(data.content, currentKey) : ''
            };
        }

        // Discard local edits and show what's stored now.
        async function loadLatest() {
            if (isSaving) return;
            try {
                const latest = await fetchLatest();
                document.getElementById('editor').value = latest.content;
                currentVersion = latest.version;
                dirty = false;
                clearTimeout(saveTimeout);
                setConflict(false);
                updateWordCount();
                updateSaveStatus('Saved', 'saved');
            } catch (error) {
                console.error('Load latest failed:', error);
                updateSaveStatus('Not saved', 'error', " · couldn't load latest");
            }
        }

        // Rebase onto the stored version and save this editor's text over it.
        async function keepMine() {
            if (isSaving) return;
            try {
                currentVersion = (await apiLoad(fileHash)).version;
                setConflict(false);
                dirty = true;
                saveIfDirty();
            } catch (error) {
                console.error('Overwrite failed:', error);
                updateSaveStatus('Not saved', 'error', " · couldn't reach the server");
            }
        }

        // Returning to a tab with no pending edits: pick up changes made
        // elsewhere now, rather than discovering them as a conflict later.
        async function refreshIfIdle() {
            if (!sessionActive || dirty || isSaving || conflict || document.hidden) return;
            const id = fileHash;
            try {
                const latest = await fetchLatest();
                // Skip if nothing changed, the user started typing or switched
                // notes meanwhile, or the note expired server-side (keep the text
                // on screen; the next save re-creates it).
                if (!latest.version || latest.version === currentVersion) return;
                if (dirty || isSaving || !sessionActive || fileHash !== id) return;
                document.getElementById('editor').value = latest.content;
                currentVersion = latest.version;
                updateWordCount();
            } catch (error) {
                console.error('Refresh failed:', error);
            }
        }

        document.getElementById('loadLatestBtn').addEventListener('click', loadLatest);
        document.getElementById('keepMineBtn').addEventListener('click', keepMine);
        document.addEventListener('visibilitychange', refreshIfIdle);

        // kind: '' (idle) | 'pending' | 'saving' | 'saved' | 'error'
        // detail is dropped on narrow screens, so keep the essential part in text.
        function updateSaveStatus(text, kind = '', detail = '') {
            const statusDiv = document.getElementById('saveStatus');
            statusDiv.querySelector('.status-text').textContent = text;
            statusDiv.querySelector('.status-detail').textContent = detail;
            statusDiv.className = 'save-status' + (kind ? ' ' + kind : '');
            statusDiv.title = text + detail;
        }

        // Prevent accidental page close
        window.addEventListener('beforeunload', function (e) {
            if (dirty || isSaving) {
                e.preventDefault();
                e.returnValue = '';
            }
        });
    