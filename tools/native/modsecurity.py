"""libModSecurity v3 C API adapter; all transactions stay in memory."""

import ctypes as C
import ctypes.util
from pathlib import Path
import re


class ModSecurity:
    def __init__(self, rules_path, with_crs=False):
        library = ctypes.util.find_library("modsecurity")
        if not library:
            raise RuntimeError("libmodsecurity is not installed")
        self.lib = C.CDLL(library)
        p, s, i, z = C.c_void_p, C.c_char_p, C.c_int, C.c_size_t
        signatures = {
            "msc_init": (p, []),
            "msc_cleanup": (None, [p]),
            "msc_who_am_i": (s, [p]),
            "msc_create_rules_set": (p, []),
            "msc_rules_cleanup": (i, [p]),
            "msc_rules_add": (i, [p, s, C.POINTER(s)]),
            "msc_rules_add_file": (i, [p, s, C.POINTER(s)]),
            "msc_new_transaction": (p, [p, p, p]),
            "msc_transaction_cleanup": (None, [p]),
            "msc_process_connection": (i, [p, s, i, s, i]),
            "msc_process_uri": (i, [p, s, s, s]),
            "msc_add_n_request_header": (i, [p, s, z, s, z]),
            "msc_process_request_headers": (i, [p]),
            "msc_append_request_body": (i, [p, s, z]),
            "msc_process_request_body": (i, [p]),
            "msc_add_n_response_header": (i, [p, s, z, s, z]),
            "msc_process_response_headers": (i, [p, i, s]),
            "msc_append_response_body": (i, [p, s, z]),
            "msc_process_response_body": (i, [p]),
            "msc_process_logging": (i, [p]),
        }
        for name, (restype, argtypes) in signatures.items():
            fn = getattr(self.lib, name)
            fn.restype, fn.argtypes = restype, argtypes
        self.engine = self.lib.msc_init()
        self.rules = self.lib.msc_create_rules_set()
        if not self.engine or not self.rules:
            raise RuntimeError("Unable to allocate ModSecurity engine")
        self.alerts = []
        callback_type = C.CFUNCTYPE(None, p, p)

        def log(_context, message):
            text = C.cast(message, s).value.decode("utf-8", errors="replace")
            self.alerts.extend(re.findall(r'\[id "(\d+)"\]', text))

        self.callback = callback_type(log)
        self.lib.msc_set_log_cb.argtypes = [p, callback_type]
        self.lib.msc_set_log_cb(self.engine, self.callback)
        self.lib.msc_set_log_cb.restype = None
        self.version = self.lib.msc_who_am_i(self.engine).decode()
        configuration = """SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html application/json
SecRequestBodyLimit 2097152
SecRequestBodyNoFilesLimit 2097152
SecResponseBodyLimit 2097152
SecTmpDir /tmp
SecUploadDir /tmp
SecAuditEngine Off
"""
        try:
            self.add(configuration)
            if with_crs:
                setup = Path("/etc/modsecurity/crs/crs-setup.conf")
                if not setup.exists():
                    raise RuntimeError("Installed CRS setup not found")
                self.add_file(setup)
                for rule in sorted(
                    Path("/usr/share/modsecurity-crs/rules").glob("*.conf")
                ):
                    self.add_file(rule)
            self.add_file(rules_path)
        except BaseException:
            self.close()
            raise

    def add(self, text):
        error = C.c_char_p()
        if self.lib.msc_rules_add(self.rules, text.encode(), C.byref(error)) < 0:
            raise RuntimeError(
                "ModSecurity configuration: " + (error.value or b"unknown").decode()
            )

    def add_file(self, path):
        error = C.c_char_p()
        if (
            self.lib.msc_rules_add_file(
                self.rules, str(Path(path).resolve()).encode(), C.byref(error)
            )
            < 0
        ):
            raise RuntimeError(
                "ModSecurity rule load: " + (error.value or b"unknown").decode()
            )

    def close(self):
        if self.rules:
            self.lib.msc_rules_cleanup(self.rules)
            self.rules = None
        if self.engine:
            self.lib.msc_cleanup(self.engine)
            self.engine = None

    def evaluate(self, request, response):
        # DetectionOnly deliberately observes all rules, even those following a deny.
        # This is alert validation, not a web-server connector/blocking test.
        self.alerts.clear()
        transaction = self.lib.msc_new_transaction(self.engine, self.rules, None)
        if not transaction:
            raise RuntimeError("Unable to allocate ModSecurity transaction")

        def call(name, *args):
            if getattr(self.lib, name)(transaction, *args) < 0:
                raise RuntimeError("ModSecurity phase failed: " + name)

        try:
            call("msc_process_connection", b"203.0.113.10", 40000, b"192.0.2.10", 80)
            start, headers, body = split_http(request)
            method, uri, version = start.split(" ", 2)
            call(
                "msc_process_uri",
                uri.encode(),
                method.encode(),
                version.removeprefix("HTTP/").encode(),
            )
            for key, value in headers:
                call("msc_add_n_request_header", key, len(key), value, len(value))
            call("msc_process_request_headers")
            # C API connectors pass decoded entity bodies. Chunk framing is removed here.
            if any(
                k.lower() == b"transfer-encoding" and b"chunked" in v.lower()
                for k, v in headers
            ):
                body = dechunk(body)
            call("msc_append_request_body", body, len(body))
            call("msc_process_request_body")
            start, headers, body = split_http(response)
            for key, value in headers:
                call("msc_add_n_response_header", key, len(key), value, len(value))
            call("msc_process_response_headers", int(start.split(" ")[1]), b"HTTP/1.1")
            call("msc_append_response_body", body, len(body))
            call("msc_process_response_body")
            call("msc_process_logging")
            return sorted(set(self.alerts))
        finally:
            self.lib.msc_transaction_cleanup(transaction)


def split_http(raw):
    head, body = raw.split("\r\n\r\n", 1)
    lines = head.split("\r\n")
    headers = [
        tuple(part.strip().encode() for part in line.split(":", 1))
        for line in lines[1:]
    ]
    return lines[0], headers, body.encode()


def dechunk(body):
    result = bytearray()
    while True:
        line, separator, body = body.partition(b"\r\n")
        if not separator:
            raise ValueError("Invalid chunk framing")
        size = int(line.split(b";", 1)[0], 16)
        if size < 0 or size > 2 * 1024 * 1024:
            raise ValueError("Invalid chunk size")
        if size == 0:
            if body != b"\r\n":
                raise ValueError("Chunk trailers are not supported in fixtures")
            return bytes(result)
        if len(body) < size + 2 or body[size : size + 2] != b"\r\n":
            raise ValueError("Truncated chunk")
        result.extend(body[:size])
        body = body[size + 2 :]
