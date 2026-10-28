#!/bin/bash
set -e
cd "$(dirname "$0")"

echo "╔═══════════════════════════════════════════════════╗"
echo "║  php2shell Lab Setup                              ║"
echo "║  CVE-2026-109618 / CVE-2026-109619                ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

# ── Webroot ──────────────────────────────────────────────

mkdir -p webroot/app webroot/api

# Default endpoint — starts a session (used by most POCs/exploits)
cat > webroot/index.php << 'PHP'
<?php
session_start();
echo "PHP " . PHP_VERSION . "\n";
echo "SAPI " . php_sapi_name() . "\n";
echo "upload_progress " . ini_get('session.upload_progress.enabled') . "\n";
echo "OK\n";
PHP

# No-session endpoint (plain PHP, no session_start)
cat > webroot/nosession.php << 'PHP'
<?php
echo "PHP " . PHP_VERSION . "\nno session_start\n";
PHP

# LFI sink — simulates real-world include vulnerability
# (WordPress plugins, custom PHP apps, etc.)
# NOTE: use isset() instead of ?? for PHP 5.6 compat (?? requires PHP 7+)
cat > webroot/vuln.php << 'PHP'
<?php
$page = isset($_GET['page']) ? $_GET['page'] : 'home';
include($page);
PHP

# Session OOM endpoint — calls session_start() which decodes session file
# Used by Chain E: if session file is ~30MB, decode OOMs
cat > webroot/session_oom.php << 'PHP'
<?php
session_start();
echo "OK " . session_id() . "\n";
PHP

# php_serialize handler endpoint — sets session handler to php_serialize
# Used by Chain C: pollutes FPM worker's PS(serializer)
cat > webroot/app_serialize.php << 'PHP'
<?php
ini_set("session.serialize_handler", "php_serialize");
session_start();
$_SESSION["init"] = time();
echo "OK\n";
PHP

# __destruct gadget endpoint — defines Evil class and starts session
# Used by Chain C trigger: handler mismatch deserializes injected object
cat > webroot/destruct_test.php << 'PHP'
<?php
class Evil {
    public $cmd;
    public function __destruct() {
        if ($this->cmd) {
            system($this->cmd);
        }
    }
}
session_start();
echo "OK\n";
PHP

# OOM trigger endpoint — allocates until memory exhausted
# Used by Chain D/E testing
cat > webroot/fatal.php << 'PHP'
<?php
$x = str_repeat("A", 64 * 1024 * 1024);
echo "OK";
PHP

# ── Per-directory session handlers (Chain C) ─────────────

# /app/ uses php_serialize handler
echo "session.serialize_handler = php_serialize" > webroot/app/.user.ini
cat > webroot/app/upload.php << 'PHP'
<?php
echo "PHP " . PHP_VERSION . "\nhandler: php_serialize\n";
PHP

# /api/ uses default php handler + defines the Evil gadget class
echo "session.serialize_handler = php" > webroot/api/.user.ini
cat > webroot/api/endpoint.php << 'PHP'
<?php
class Evil {
    public $cmd;
    public function __destruct() {
        if ($this->cmd) {
            file_put_contents("/tmp/rce_proof.txt", shell_exec($this->cmd), FILE_APPEND);
        }
    }
}
session_start();
echo "OK\n";
PHP

# ── PHP config (FPM) ────────────────────────────────────

cat > php.ini << 'INI'
[Session]
session.save_handler = files
session.save_path = /tmp/sessions
session.use_strict_mode = 0
session.use_cookies = 1
session.use_only_cookies = 0
session.upload_progress.enabled = On
session.upload_progress.cleanup = Off
session.upload_progress.prefix = upload_progress_
session.upload_progress.name = PHP_SESSION_UPLOAD_PROGRESS
session.upload_progress.freq = 1%
session.upload_progress.min_freq = 0

[PHP]
display_errors = On
error_reporting = E_ALL
max_execution_time = 60
post_max_size = 128M
upload_max_filesize = 128M
file_uploads = On
memory_limit = 32M
INI

# ── PHP config (Apache mod_php) ─────────────────────────

cat > php-apache.ini << 'INI'
; Low memory_limit to make OOM easy to trigger (Chain D)
memory_limit = 32M
post_max_size = 256M
upload_max_filesize = 256M
max_input_vars = 100000
max_file_uploads = 100000
display_errors = On
error_reporting = E_ALL
session.upload_progress.enabled = On
session.upload_progress.cleanup = Off
session.save_path = /tmp
INI

# ── Nginx config (multi-backend) ───────────────────────

cat > nginx.conf << 'NGINX'
# Use Docker embedded DNS so upstream names resolve at runtime, not at startup.
# Without this, nginx exits fatally if any FPM container isn't ready yet.
resolver 127.0.0.11 valid=5s;

# PHP 5.6.40 (EOL)
server {
    listen 56;
    root /var/www/html; index index.php; client_max_body_size 128m;
    location / { try_files $uri $uri/ /index.php?$query_string; }
    location ~ \.php$ {
        set $backend php56-fpm:9000;
        fastcgi_pass $backend;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_read_timeout 120; fastcgi_request_buffering off;
    }
}

# PHP 7.4.33 (EOL)
server {
    listen 74;
    root /var/www/html; index index.php; client_max_body_size 128m;
    location / { try_files $uri $uri/ /index.php?$query_string; }
    location ~ \.php$ {
        set $backend php74-fpm:9000;
        fastcgi_pass $backend;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_read_timeout 120; fastcgi_request_buffering off;
    }
}

# PHP 8.0.30 (EOL)
server {
    listen 80;
    root /var/www/html; index index.php; client_max_body_size 128m;
    location / { try_files $uri $uri/ /index.php?$query_string; }
    location ~ \.php$ {
        set $backend php80-fpm:9000;
        fastcgi_pass $backend;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_read_timeout 120; fastcgi_request_buffering off;
    }
}

# PHP 8.1.31 (EOL)
server {
    listen 81;
    root /var/www/html; index index.php; client_max_body_size 128m;
    location / { try_files $uri $uri/ /index.php?$query_string; }
    location ~ \.php$ {
        set $backend php81-fpm:9000;
        fastcgi_pass $backend;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_read_timeout 120; fastcgi_request_buffering off;
    }
}

# PHP 8.2.34 (vulnerable)
server {
    listen 82;
    root /var/www/html; index index.php; client_max_body_size 128m;
    location / { try_files $uri $uri/ /index.php?$query_string; }
    location ~ \.php$ {
        set $backend php82-fpm:9000;
        fastcgi_pass $backend;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_read_timeout 120; fastcgi_request_buffering off;
    }
}

# PHP 8.3.35 (vulnerable)
server {
    listen 83;
    root /var/www/html; index index.php; client_max_body_size 128m;
    location / { try_files $uri $uri/ /index.php?$query_string; }
    location ~ \.php$ {
        set $backend php83-fpm:9000;
        fastcgi_pass $backend;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_read_timeout 120; fastcgi_request_buffering off;
    }
}

# PHP 8.4.26 (vulnerable)
server {
    listen 84;
    root /var/www/html; index index.php; client_max_body_size 128m;
    location / { try_files $uri $uri/ /index.php?$query_string; }
    location ~ \.php$ {
        set $backend php84-fpm:9000;
        fastcgi_pass $backend;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_read_timeout 120; fastcgi_request_buffering off;
    }
}

# PHP 8.2.35 (PATCHED)
server {
    listen 85;
    root /var/www/html; index index.php; client_max_body_size 128m;
    location / { try_files $uri $uri/ /index.php?$query_string; }
    location ~ \.php$ {
        set $backend php82p-fpm:9000;
        fastcgi_pass $backend;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_read_timeout 120; fastcgi_request_buffering off;
    }
}
NGINX

# ── FPM pool config (single worker for Chain E) ────────

cat > www.conf << 'FPM'
[www]
user = www-data
group = www-data
listen = 9000
pm = static
pm.max_children = 1
FPM

# ── Docker Compose ──────────────────────────────────────

cat > docker-compose.yml << 'YAML'
services:
  # ── EOL versions (no official fix) ─────────────────────
  php56-fpm:
    image: php:5.6.40-fpm
    container_name: php2shell-fpm-56
    volumes:
      - ./webroot:/var/www/html
      - ./php.ini:/usr/local/etc/php/php.ini
      - ./www.conf:/usr/local/etc/php-fpm.d/www.conf
    security_opt: [seccomp:unconfined]
    privileged: true
    command: >
      bash -c "mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions && php-fpm"

  php74-fpm:
    image: php:7.4.33-fpm
    container_name: php2shell-fpm-74
    volumes:
      - ./webroot:/var/www/html
      - ./php.ini:/usr/local/etc/php/php.ini
      - ./www.conf:/usr/local/etc/php-fpm.d/www.conf
    security_opt: [seccomp:unconfined]
    privileged: true
    command: >
      bash -c "mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions && php-fpm"

  php80-fpm:
    image: php:8.0.30-fpm
    container_name: php2shell-fpm-80
    volumes:
      - ./webroot:/var/www/html
      - ./php.ini:/usr/local/etc/php/php.ini
      - ./www.conf:/usr/local/etc/php-fpm.d/www.conf
    security_opt: [seccomp:unconfined]
    privileged: true
    command: >
      bash -c "mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions && php-fpm"

  php81-fpm:
    image: php:8.1.31-fpm
    container_name: php2shell-fpm-81
    volumes:
      - ./webroot:/var/www/html
      - ./php.ini:/usr/local/etc/php/php.ini
      - ./www.conf:/usr/local/etc/php-fpm.d/www.conf
    security_opt: [seccomp:unconfined]
    privileged: true
    command: >
      bash -c "mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions && php-fpm"

  # ── Supported versions (last vulnerable before patch) ──
  php82-fpm:
    image: php:8.2.34-fpm
    container_name: php2shell-fpm-82
    volumes:
      - ./webroot:/var/www/html
      - ./php.ini:/usr/local/etc/php/php.ini
      - ./www.conf:/usr/local/etc/php-fpm.d/www.conf
    security_opt: [seccomp:unconfined]
    privileged: true
    command: >
      bash -c "mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions && php-fpm"

  php83-fpm:
    image: php:8.3.35-fpm
    container_name: php2shell-fpm-83
    volumes:
      - ./webroot:/var/www/html
      - ./php.ini:/usr/local/etc/php/php.ini
      - ./www.conf:/usr/local/etc/php-fpm.d/www.conf
    security_opt: [seccomp:unconfined]
    privileged: true
    command: >
      bash -c "mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions && php-fpm"

  php84-fpm:
    image: php:8.4.26-fpm
    container_name: php2shell-fpm-84
    volumes:
      - ./webroot:/var/www/html
      - ./php.ini:/usr/local/etc/php/php.ini
      - ./www.conf:/usr/local/etc/php-fpm.d/www.conf
    security_opt: [seccomp:unconfined]
    privileged: true
    command: >
      bash -c "mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions && php-fpm"

  # ── Patched (differential testing) ─────────────────────
  php82p-fpm:
    image: php:8.2.35-fpm
    container_name: php2shell-fpm-82p
    volumes:
      - ./webroot:/var/www/html
      - ./php.ini:/usr/local/etc/php/php.ini
      - ./www.conf:/usr/local/etc/php-fpm.d/www.conf
    security_opt: [seccomp:unconfined]
    privileged: true
    command: >
      bash -c "mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions && php-fpm"

  # ── Nginx ──────────────────────────────────────────────
  nginx:
    image: nginx:alpine
    container_name: php2shell-nginx
    ports:
      - "18056:56"    # → PHP 5.6.40 (EOL)
      - "18074:74"    # → PHP 7.4.33 (EOL)
      - "18080:80"    # → PHP 8.0.30 (EOL)
      - "18081:81"    # → PHP 8.1.31 (EOL)
      - "18082:82"    # → PHP 8.2.34 (vulnerable)
      - "18083:83"    # → PHP 8.3.35 (vulnerable)
      - "18084:84"    # → PHP 8.4.26 (vulnerable)
      - "18085:85"    # → PHP 8.2.35 (patched)
    volumes:
      - ./webroot:/var/www/html
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
    depends_on:
      - php56-fpm
      - php74-fpm
      - php80-fpm
      - php81-fpm
      - php82-fpm
      - php83-fpm
      - php84-fpm
      - php82p-fpm

  # ── Apache mod_php ─────────────────────────────────────
  apache:
    image: php:8.2.34-apache
    container_name: php2shell-apache
    ports: ["18091:80"]
    volumes:
      - ./webroot:/var/www/html
      - ./php-apache.ini:/usr/local/etc/php/php.ini
    command: >
      bash -c "mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions && apache2-foreground"

  apache56:
    image: php:5.6.40-apache
    container_name: php2shell-apache-56
    ports: ["18092:80"]
    volumes:
      - ./webroot:/var/www/html
      - ./php-apache.ini:/usr/local/etc/php/php.ini
    command: >
      bash -c "mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions && apache2-foreground"

  apache74:
    image: php:7.4.33-apache
    container_name: php2shell-apache-74
    ports: ["18093:80"]
    volumes:
      - ./webroot:/var/www/html
      - ./php-apache.ini:/usr/local/etc/php/php.ini
    command: >
      bash -c "mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions && apache2-foreground"
YAML

# ── Start ───────────────────────────────────────────────

echo "Starting containers..."
docker compose up -d

# Wait for services
echo "Waiting for services..."
sleep 8

# Verify
echo ""
echo "Verifying..."
check() { curl -sf "http://127.0.0.1:$1/index.php" 2>/dev/null | head -1; }
printf "  %-14s : %s  (%s)\n" "5.6.40 FPM"    "$(check 18056)" "http://127.0.0.1:18056"
printf "  %-14s : %s  (%s)\n" "7.4.33 FPM"    "$(check 18074)" "http://127.0.0.1:18074"
printf "  %-14s : %s  (%s)\n" "8.0.30 FPM"    "$(check 18080)" "http://127.0.0.1:18080"
printf "  %-14s : %s  (%s)\n" "8.1.31 FPM"    "$(check 18081)" "http://127.0.0.1:18081"
printf "  %-14s : %s  (%s)\n" "8.2.34 FPM"    "$(check 18082)" "http://127.0.0.1:18082"
printf "  %-14s : %s  (%s)\n" "8.3.35 FPM"    "$(check 18083)" "http://127.0.0.1:18083"
printf "  %-14s : %s  (%s)\n" "8.4.26 FPM"    "$(check 18084)" "http://127.0.0.1:18084"
printf "  %-14s : %s  (%s) %s\n" "8.2.35 FPM" "$(check 18085)" "http://127.0.0.1:18085" "[PATCHED]"
printf "  %-14s : %s  (%s)\n" "8.2.34 Apache" "$(check 18091)" "http://127.0.0.1:18091"
printf "  %-14s : %s  (%s)\n" "5.6.40 Apache" "$(check 18092)" "http://127.0.0.1:18092"
printf "  %-14s : %s  (%s)\n" "7.4.33 Apache" "$(check 18093)" "http://127.0.0.1:18093"

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  php2shell Lab ready!                                           ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║                                                                 ║"
echo "║  FPM + nginx:                                                   ║"
echo "║    PHP 5.6.40  → :18056   PHP 8.2.34  → :18082                 ║"
echo "║    PHP 7.4.33  → :18074   PHP 8.3.35  → :18083                 ║"
echo "║    PHP 8.0.30  → :18080   PHP 8.4.26  → :18084                 ║"
echo "║    PHP 8.1.31  → :18081   PHP 8.2.35  → :18085 [PATCHED]       ║"
echo "║                                                                 ║"
echo "║  Apache mod_php (Chain D — OOM):                                ║"
echo "║    PHP 5.6.40  → :18092                                        ║"
echo "║    PHP 7.4.33  → :18093                                        ║"
echo "║    PHP 8.2.34  → :18091                                        ║"
echo "║                                                                 ║"
echo "║  Exploit:                                                       ║"
echo "║    cd ../exploit                                                ║"
echo "║    python3 chain_a_session_lfi.py --target http://...:PORT      ║"
echo "║    python3 chain_c_mismatch_rce.py --target http://...:PORT     ║"
echo "║                                                                 ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
