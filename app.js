
        let currentKey = null;       // AES-GCM key, non-extractable; the passphrase itself isn't kept
        let currentToken = '';       // base64 write token proving knowledge of the passphrase
        let currentSalt = null;
        let currentKdf = '';         // how this note's key is derived, fixed when it was created
        let currentVersion = '';     // server version this editor is based on ('' = note not created yet)
        let currentName = '';        // the note's memorable name, '' if it has none
        let pendingName = '';        // name typed into the URL, claimed after the first save
        let conflict = false;        // a save hit 409; autosave pauses until the user resolves it
        let fileHash = '';
        let saveTimeout = null;
        let retryAttempt = -1;       // index into SAVE_RETRY_BACKOFF (-1 = not retrying)
        let isWorking = false;       // login-in-progress guard only
        let isSaving = false;        // save-in-flight guard
        let dirty = false;           // unsaved edits exist
        let sessionActive = false;   // true once login succeeds, false on logout

        // How a note's key is derived. The note records this when it is
        // created and keeps it for life: raising the cost for new notes must
        // never change the key of an existing one, or its owner is locked out.
        // Notes made before the record existed used LEGACY_KDF.
        const CURRENT_KDF = 'pbkdf2-sha256:600000';
        const LEGACY_KDF = 'pbkdf2-sha256:250000';
        const KDF_RE = /^pbkdf2-sha256:([0-9]{1,9})$/;

        // null for anything this version can't run — better to say so than to
        // derive the wrong key and call it a wrong passphrase.
        function parseKdf(spec) {
            const m = KDF_RE.exec(spec || '');
            return m ? { hash: 'SHA-256', iterations: Number(m[1]) } : null;
        }

        // Every request gets a deadline. Without one a stalled connection (a
        // dead tunnel, a captive portal) leaves "Saving..." on screen forever
        // and nothing ever retries.
        const REQUEST_TIMEOUT = 15000;

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
                ? (pendingName
                    ? `Nothing is saved at “${pendingName}” yet. Choose a passphrase and this note takes that name.`
                    : 'Choose a passphrase to encrypt it. Notes vanish after 2 days without being opened or edited.')
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
        // A memorable name a note can also answer to: 3-32 chars, lowercase
        // letters, digits and dashes. Never a note ID (32 hex chars).
        const NAME_RE = /^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$/;

        function isName(s) {
            return NAME_RE.test(s) && !NOTE_ID_RE.test(s);
        }

        // What the URL points at: a note ID, a name, or nothing.
        function refFromUrl() {
            const h = (location.hash || '').slice(1).toLowerCase();
            return NOTE_ID_RE.test(h) || isName(h) ? h : '';
        }

        // The full URL for a note, by link or by name.
        function noteUrl(ref) {
            return location.origin + location.pathname + '#' + ref;
        }

        function setUrlRef(ref) {
            history.replaceState(null, '', '#' + ref);
            document.getElementById('linkField').value = location.href;
        }

        function randomNoteId() {
            const bytes = new Uint8Array(16);
            crypto.getRandomValues(bytes);
            return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
        }

        // --- CRYPTOGRAPHY ---

        // Chunked conversion helpers that avoid the call-stack limit on
        // large payloads.  `String.fromCharCode.apply()` blows the stack
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
        async function deriveSecrets(password, salt, kdf) {
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
                    iterations: kdf.iterations,
                    hash: kdf.hash
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

        // Every note lives at a random link, and may also answer to a name.
        // A visitor landing without either gets a freshly-generated link.
        let freshNote = false;
        fileHash = refFromUrl();
        if (!fileHash) {
            fileHash = randomNoteId();
            freshNote = true;
        }
        setUrlRef(fileHash);
        renderLoginMode();

        // Loads never write, so it is cheap to ask up front whether this link
        // or name has a note behind it, and label the screen accordingly.
        if (!freshNote) {
            apiLoad(fileHash).then(data => {
                if (data.salt || sessionActive) return;
                freshNote = true;
                if (isName(fileHash)) {
                    // The name is unclaimed: the note gets a random link now and
                    // takes the name once it has been saved.
                    pendingName = fileHash;
                    fileHash = randomNoteId();
                }
                renderLoginMode();
            }).catch(() => { /* offline: assume the note exists and let login report it */ });
        }
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

        // Every API call is one JSON POST with a deadline. A rejected call
        // carries err.status when the server answered; a call that never got
        // an answer (offline, DNS, or past REQUEST_TIMEOUT) carries none, so
        // callers can tell "the server said no" from "no server".
        async function apiPost(path, payload, fallbackMessage) {
            let response;
            try {
                response = await fetch(path, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                    signal: AbortSignal.timeout(REQUEST_TIMEOUT)
                });
            } catch {
                throw new Error("Couldn't reach the server");
            }
            // A proxy error page isn't JSON; fall back to the status code.
            const data = await response.json().catch(() => ({}));
            if (!response.ok) {
                const err = new Error(data.error || fallbackMessage);
                err.status = response.status;
                throw err;
            }
            return data;
        }

        function apiLoad(id) {
            return apiPost('/api/load', { hash: id }, 'Load failed');
        }

        // The salt only matters on the save that creates the note; the server
        // ignores it afterwards and keeps the original.
        // `base` is the version the edit started from; the server answers 409 if
        // the note has moved on since (another tab or device saved first).
        // `kdf` is recorded on the save that creates the note and ignored after.
        function apiSave(id, content, token, salt, base, kdf) {
            return apiPost('/api/save',
                { hash: id, content, token, salt: toBase64(salt), base, kdf }, 'Save failed');
        }

        function apiName(ref, name, token) {
            return apiPost('/api/name', { hash: ref, name, token }, 'Could not set the name');
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
                // An existing note is unlocked with the cost it was made with;
                // a note being created now gets today's.
                const kdfSpec = data.salt ? (data.kdf || LEGACY_KDF) : CURRENT_KDF;
                const kdf = parseKdf(kdfSpec);
                if (!kdf) {
                    throw new Error('Unsupported note format');
                }
                const salt = data.salt ? base64ToUint8Array(data.salt) : randomSalt();
                const { key, token } = await deriveSecrets(password, salt, kdf);
                if (data.content) {
                    content = await decrypt(data.content, key);
                }
                currentKdf = kdfSpec;
                currentSalt = salt;
                currentKey = key;
                currentToken = token;
                currentVersion = data.version;
                currentName = data.name || '';
                renderNameButton();
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
                    : error.message.includes('Unsupported')
                        ? 'This note was made by a newer version of Paper — update the page and try again'
                        : error.status === 429
                            ? 'Too many attempts — wait a few seconds and try again'
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
            let lastStatus = 0;

            try {
                const encryptedContent = await encrypt(content, currentKey);

                const saved = await apiSave(fileHash, encryptedContent, currentToken,
                    currentSalt, currentVersion, currentKdf);
                if (!sessionActive) return; // locked while this save was in flight
                currentVersion = saved.version;
                retryAttempt = -1;
                renderNameButton(); // the note exists now, so it can be named
                if (pendingName) claimPendingName();
                updateSaveStatus(dirty ? 'Unsaved' : 'Saved', dirty ? 'pending' : 'saved');
            } catch (error) {
                console.error('Save failed:', error);
                dirty = true;
                failed = true;
                // 403: the note at this link belongs to a different passphrase
                // (e.g. someone else created it first). Retrying can't fix that.
                // 413: the note is over the server's size limit. Retrying the
                // same text can't succeed; the next edit tries again.
                rejected = error.status === 403 || error.status === 413;
                lastStatus = error.status;
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
                    updateSaveStatus('Not saved', 'error', lastStatus === 413
                        ? ' · note too large, shorten it'
                        : ' · wrong passphrase for this note');
                } else if (dirty && sessionActive) {
                    const delay = failed
                        ? SAVE_RETRY_BACKOFF[retryAttempt = Math.min(retryAttempt + 1, SAVE_RETRY_BACKOFF.length - 1)]
                        : 1500; // edits arrived mid-save: normal debounce
                    if (failed) updateSaveStatus('Not saved', 'error',
                        `${lastStatus === 429 ? ' · too many saves' : ''} · retrying in ${delay / 1000}s`);
                    clearTimeout(saveTimeout);
                    saveTimeout = setTimeout(saveIfDirty, delay);
                }
            }
        }

        function copyToClipboard(btn, text, fallbackFieldId) {
            const label = btn.textContent;
            navigator.clipboard.writeText(text).then(() => {
                btn.textContent = 'Copied!';
                setTimeout(() => { btn.textContent = label; }, 1500);
            }).catch(() => {
                // Clipboard blocked (e.g. insecure context): fall back to selecting the link
                const field = document.getElementById(fallbackFieldId);
                if (field && !field.closest('[hidden]')) field.select();
            });
        }

        function copyLink(btn) {
            copyToClipboard(btn, location.href, 'linkField');
        }

        function newNote() {
            const id = randomNoteId();
            fileHash = id;
            setUrlRef(id);
            freshNote = true;
            currentKey = null;
            currentToken = '';
            currentSalt = null;
            currentKdf = '';
            currentVersion = '';
            currentName = '';
            pendingName = '';
            setConflict(false);
            renderNameButton();
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

        // Resolves when work settles or the deadline passes, whichever comes
        // first — so a wedged request can delay the UI, never block it.
        function withDeadline(work, ms) {
            return Promise.race([
                work.catch(() => { }),
                new Promise(resolve => setTimeout(resolve, ms))
            ]);
        }

        // Wait out a save already in flight, then save what's still unsaved.
        async function flushSave() {
            while (isSaving) await new Promise(r => setTimeout(r, 100));
            if (dirty && !conflict) await saveIfDirty();
        }

        // Locking with pending edits first tries to save them right away; the
        // user is only asked when that isn't possible (offline, conflict, ...).
        // The flush gets one deadline covering the whole attempt: a failing
        // save ends up back in the retry ladder, and waiting on that ladder
        // would leave the note un-lockable for as long as the outage lasts.
        async function lockNote() {
            if (!sessionActive) return;
            const lockBtn = document.getElementById('lockBtn');
            lockBtn.disabled = true;
            try {
                if (!conflict && (dirty || isSaving)) {
                    clearTimeout(saveTimeout);
                    await withDeadline(flushSave(), REQUEST_TIMEOUT + 2000);
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
            currentKdf = '';
            currentVersion = '';
            currentName = '';
            pendingName = '';
            setConflict(false);
            renderNameButton();
            fileHash = refFromUrl() || fileHash;
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

        // --- NAMES (a memorable link for this note) ---
        function renderNameButton() {
            const btn = document.getElementById('nameBtn');
            btn.textContent = currentName ? '#' + currentName : 'Name link';
            // A note can only be named once it exists, i.e. after its first save.
            btn.disabled = !currentVersion;
            btn.title = !currentVersion
                ? 'Type something first — the note is created on its first save'
                : currentName
                    ? `This note also answers to #${currentName} — click to rename`
                    : 'Give this note a memorable link';
        }

        // A name typed into the URL is claimed once the note actually exists.
        async function claimPendingName() {
            const wanted = pendingName;
            pendingName = '';
            try {
                const result = await apiName(fileHash, wanted, currentToken);
                currentName = result.name;
                setUrlRef(currentName);
                renderNameButton();
            } catch (error) {
                // Someone else got there first: fall back to the random link so
                // the note stays reachable, and say so.
                setUrlRef(fileHash);
                renderNameButton();
                showNameDialog(error.status === 409
                    ? `“${wanted}” was taken while you were typing. Your note is safe at its random link — pick another name, or close this and copy the link.`
                    : `Couldn't claim “${wanted}”: ${error.message}`);
            }
        }

        function showNameDialog(message = '') {
            const dialog = document.getElementById('nameDialog');
            const input = document.getElementById('nameInput');
            input.value = currentName;
            document.getElementById('nameRemoveBtn').hidden = !currentName;
            document.getElementById('nameError').textContent = message;

            // Naming puts the name in the address bar, and the server never
            // hands the random link back — a note reopened at its name can't
            // learn its own link. So offer the link for copying while this
            // session still knows it, and say why it matters.
            const linkBox = document.getElementById('nameLinkBox');
            const knowsLink = NOTE_ID_RE.test(fileHash);
            linkBox.hidden = !knowsLink;
            if (knowsLink) {
                document.getElementById('nameLinkField').value = noteUrl(fileHash);
            }

            dialog.showModal();
            input.focus();
            input.select();
        }

        async function submitName(name) {
            const errorBox = document.getElementById('nameError');
            if (name && !isName(name)) {
                errorBox.textContent = 'Use 3-32 lowercase letters, numbers or dashes.';
                return;
            }
            const saveBtn = document.getElementById('nameSaveBtn');
            saveBtn.disabled = true;
            try {
                const result = await apiName(fileHash, name, currentToken);
                currentName = result.name;
                setUrlRef(currentName || fileHash);
                renderNameButton();
                document.getElementById('nameDialog').close();
            } catch (error) {
                errorBox.textContent = error.message;
            } finally {
                saveBtn.disabled = false;
            }
        }

        document.getElementById('nameBtn').addEventListener('click', () => showNameDialog());
        document.getElementById('nameLinkCopyBtn').addEventListener('click',
            e => copyToClipboard(e.currentTarget, noteUrl(fileHash), 'nameLinkField'));
        document.getElementById('nameLinkField').addEventListener('focus', e => e.target.select());
        document.getElementById('nameForm').addEventListener('submit', e => {
            e.preventDefault();
            submitName(document.getElementById('nameInput').value.trim().toLowerCase());
        });
        document.getElementById('nameRemoveBtn').addEventListener('click', () => submitName(''));
        document.getElementById('nameCancelBtn').addEventListener('click', () => document.getElementById('nameDialog').close());

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
    