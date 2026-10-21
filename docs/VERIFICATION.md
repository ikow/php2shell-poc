# Live-Lab Verification — CVE-2026-109618 / 109619

**Date:** 2026-10-21
**Environment:** Rocky Linux 9, Docker, PHP 8.2.34-fpm (vulnerable) vs PHP 8.2.35-fpm (patched), nginx 1.31.7, lab reachable on `127.0.0.1:18080` (8.2.34) and `127.0.0.1:18081` (8.2.35).

## 1. Bugs found in the repository before verification

Four issues prevented the shipped PoCs/lab from working as documented (a fifth surfaced during verification):

| # | Issue | Impact | Fix |
|---|-------|--------|-----|
| 1 | `lab/setup.sh` used `image: php:8.2-fpm` | After the 2026-10-21 patch release the tag resolves to 8.2.35+ (fixed) — every chain silently fails | Pin `php:8.2.34-fpm` |
| 2 | `verify_handler_mismatch.py` sent the SID only as a multipart form field | PHP ignores the field in this configuration; the progress write lands on a random SID, so **no session file is created** | Send `Cookie: PHPSESSID=<sid>` |
| 3 | `lab/setup.sh` copied `nosession.php` to `api/endpoint.php` | The read endpoint never calls `session_start()`, so the php handler never decodes the session — `__destruct` can never fire | Ship an endpoint that calls `session_start()` (+ a `Pwn` gadget class) |
| 4 | Hand-written payload used `O:4:"Pwn"` | `Pwn` is 3 bytes; the parser reads `Pwn"` as the class name and aborts — the object is never created | Build gadgets with exact length prefixes (`build_gadget()` in the PoC) |
| 5 | The PoC's read step was a multipart POST | A multipart POST starts the session early (rfc1867 callback → `php_rinit_session(0)`) before the script runs; the script's `session_start()` then no-ops and the early decode — which runs before any user class is loaded — only yields `__PHP_Incomplete_Class`, so `__destruct` never fires | Trigger the read with a plain GET so the script's own `session_start()` performs the decode |

## 2. Mechanism (confirmed against PHP-8.2.34 source)

1. **Write** — `php_session_rfc1867_callback` (`ext/session/session.c`) runs during POST parsing, *before RINIT*. On `MULTIPART_EVENT_FILE_START` it calls `php_rinit_session(0)`, adopts the SID (cookie preferred, form field via trans-sid fallback), and `php_session_rfc1867_update()` stores `upload_progress_<name>` — including the **raw multipart filename** (`\"` is unescaped by the rfc1867 parser) — into `$_SESSION` and flushes it with the request's serialize handler. No `session_start()` needed; `session.upload_progress.cleanup = Off` keeps the data.
2. **Handler mismatch** — `PS_SERIALIZER_DECODE_FUNC(php)` splits the file at the **first `|`** and feeds everything after it to `php_var_unserialize`. A file written by the `php_serialize` handler therefore yields `key|O:3:"Pwn":1:{…}` → the object is instantiated; the trailing bytes then fail the next `|` scan.
3. **Destruction** — decode failure triggers `php_session_cancel_decode()` → `php_session_destroy()` → `$_SESSION` is torn down → the injected object is destroyed → **`__destruct` fires**. The session file is unlinked (`s_destroy`), which is a useful forensic indicator.
4. **CVE window** — the same decode also happens inside the upload-progress update path *before RINIT*, where no user class is loaded yet. On 8.2.34 objects are instantiated with full semantics (autoload / `__wakeup` / `unserialize_callback_func`); the 8.2.35 patch sets `incomplete_classes_only` there, so objects degrade to `__PHP_Incomplete_Class`.

## 3. Differential test matrix

Gadget: `Pwn` (defined by the read endpoint) or `PrePwn` (loaded via `opcache.preload`, i.e. visible pre-RINIT). Payload delivered as multipart filename: `x|O:3:"Pwn":1:{s:3:"cmd";s:2:"id";}`.

| Chain | 8.2.34 | 8.2.35 | Verdict |
|-------|--------|--------|---------|
| A: filename → session file → LFI `include()` | ✅ `uid=33(www-data)` + `RCE_LFI` | ✅ (write path unchanged) | Logic bug, **not** fixed by the patch |
| C: handler mismatch + app `session_start()` decode | ✅ `uid=33(www-data)` + marker | ✅ `uid=33(www-data)` + marker | Misconfiguration, **not** fixed by the patch |
| CVE: handler mismatch + early (pre-RINIT) decode, preloaded gadget | ✅ `uid=33(www-data)` + `PRELOAD_DESTRUCT php=8.2.34`; warning shows output started at `preload.php:11` | ❌ no output, no marker | **This is the CVE-2026-109618 fix** |

## 4. Key evidence

8.2.34, early-decode trigger (`POST /api/endpoint.php` with upload progress, no `session_start()`):

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Warning: PHP Request Startup: Failed to decode session object. Session has been destroyed in Unknown on line 0
Warning: PHP Request Startup: Session cookie cannot be sent after headers have already been sent (output started at /var/www/html/preload.php:11) in Unknown on line 0
```

`/tmp/pwned_marker`: `PRELOAD_DESTRUCT php=8.2.34 pid=10`

8.2.35, identical request: same decode-failure warning, **no** `uid=` output, **no** marker.

Session file after the write (php_serialize handler, `/app/upload.php`):

```
a:1:{s:17:"upload_progress_x";a:5:{…s:5:"files";a:1:{i:0;a:7:{…s:4:"name";s:35:"x|O:3:"Pwn":1:{s:3:"cmd";s:2:"id";}";…}}}}
```

## 5. What the 8.2.35 patch actually changes (diff PHP-8.2.34 → PHP-8.2)

* `php_session_rfc1867_update()` / `php_session_rfc1867_cleanup()`: wrap initialize+flush with `PS(in_rfc1867_update) = true`, which makes `php_session_(un)serialize_init()` enable `incomplete_classes_only` — no autoloading, no `unserialize_callback_func`, no `__wakeup()`/`__unserialize()`, objects written back unchanged.
* `php_session_rfc1867_callback()`: skip when `PG(modules_activated)` (`request_parse_body()` corrupts the session); clear session globals at `MULTIPART_EVENT_START`; delete the early-populated `$_SESSION` at `MULTIPART_EVENT_END`.
* The patch does **not** sanitize the stored filename, does **not** reset `PS(serializer)` across requests, and does **not** touch the normal `session_start()` decode path.

## 6. Reproducing the differential environment

`lab/diff/` ships the exact stack used above (paths are relative to `lab/`):

```bash
cd lab && ./setup.sh                      # single-container lab (:18080, 8.2.34)
cd diff && docker compose up -d           # adds :18081 running 8.2.35
docker compose exec php php -v            # 8.2.34 ...
docker compose exec php-patched php -v    # 8.2.35 ...
```

* `diff/php.ini` mounts into **both** containers; its `opcache.preload` +
  `opcache.preload_user = root` pair is what makes `PrePwn` visible before RINIT
  (the `preload_user` line is mandatory — without it php-fpm fatals on start).
* `diff/preload.php` must be present in `webroot/` (it is mounted from `../webroot`).
* Run the preloaded-gadget CVE path against either port:

```bash
python3 ../poc/verify_handler_mismatch.py --target http://127.0.0.1:18080 \
    --class PrePwn --prop cmd=id --write-path /app/upload.php --read-path /api/endpoint.php
# expect: uid=... in the response on :18080, nothing on :18081
docker compose exec php cat /tmp/pwned_marker          # PRELOAD_DESTRUCT php=8.2.34
docker compose exec php-patched cat /tmp/pwned_marker  # (no such file)
```

## 7. Calibrated conclusions

1. The CVE-2026-109618 fix is the `incomplete_classes_only` hardening of the pre-RINIT upload-progress decode. Exploitation needs a gadget class that is visible before RINIT — in this lab via `opcache.preload`; without that, injected objects degrade to `__PHP_Incomplete_Class` even on 8.2.34.
2. Chains A (filename → LFI) and C (app-level handler mismatch) are **not** addressed by the patch and still yield RCE on 8.2.35. They rely on an app LFI and on two directories sharing `session.save_path` with different `serialize_handler` values respectively.
3. `session.upload_progress.enabled = Off` remains the effective mitigation for the CVE path; `session.use_only_cookies = On` does not affect it (the SID is adopted from the cookie anyway).
