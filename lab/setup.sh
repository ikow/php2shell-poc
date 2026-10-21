#!/bin/bash
set -e

echo "Setting up PHP 8.2.34 vulnerable lab environment..."

cd "$(dirname "$0")"

# Create webroot
mkdir -p webroot/app webroot/api webroot/reader

cat > webroot/index.php << 'EOF'
<?php
session_start();
echo "PHP " . PHP_VERSION . "\n";
echo "SAPI " . php_sapi_name() . "\n";
echo "upload_progress " . ini_get('session.upload_progress.enabled') . "\n";
echo "OK\n";
EOF

cat > webroot/nosession.php << 'EOF'
<?php
echo "PHP " . PHP_VERSION . "\nno session_start\n";
EOF

# Directory with php_serialize handler
echo "session.serialize_handler = php_serialize" > webroot/app/.user.ini
cp webroot/nosession.php webroot/app/upload.php

# Directory with php handler.
# endpoint.php MUST call session_start(): the php handler only decodes the
# session file when a script starts a session. The original lab shipped a
# nosession.php copy here, so the mismatch chain could never fire.
# The Pwn gadget class stands in for an application-defined POP gadget.
cat > webroot/api/endpoint.php << 'EOF'
<?php
class Pwn {
    public $cmd = 'id';
    public function __destruct() {
        file_put_contents('/tmp/pwned_marker', 'DESTRUCT cmd=' . $this->cmd . ' pid=' . getmypid() . "\n", FILE_APPEND);
        system($this->cmd);
    }
}
session_start();
var_dump($_SESSION);
echo "READ_DONE\n";
EOF

# LFI simulation (for Chain 1 verification)
cat > webroot/vuln.php << 'EOF'
<?php
$page = $_GET['page'] ?? 'home';
include($page);
EOF

# PHP configuration
cat > php.ini << 'EOF'
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
file_uploads = On
post_max_size = 128M
upload_max_filesize = 128M
EOF

# Nginx config
cat > nginx.conf << 'EOF'
server {
    listen 80;
    root /var/www/html;
    index index.php;
    client_max_body_size 128m;
    location / { try_files $uri $uri/ /index.php?$query_string; }
    location ~ \.php$ {
        fastcgi_pass php:9000;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_request_buffering off;
    }
}
EOF

# Docker Compose
cat > docker-compose.yml << 'EOF'
services:
  php:
    # Pin the vulnerable build: php:8.2-fpm now resolves to 8.2.35+, which
    # contains the CVE-2026-109618 fix (incomplete_classes_only in the
    # rfc1867 upload-progress update path) and breaks every chain below.
    image: php:8.2.34-fpm
    container_name: php2shell-lab
    ports: ["9000:9000"]
    volumes:
      - ./webroot:/var/www/html
      - ./php.ini:/usr/local/etc/php/php.ini
    security_opt: [seccomp:unconfined]
    privileged: true
    command: >
      bash -c "mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions && php-fpm"

  nginx:
    image: nginx:alpine
    container_name: php2shell-nginx
    ports: ["18080:80"]
    volumes:
      - ./webroot:/var/www/html
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
    depends_on: [php]
EOF

echo "Starting containers..."
docker compose up -d --build

echo ""
echo "Lab ready!"
echo "  HTTP: http://127.0.0.1:18080"
echo "  FCGI: 127.0.0.1:9000"
echo ""
echo "Run POCs:"
echo "  python3 ../poc/verify_session_injection.py"
echo "  python3 ../poc/verify_handler_mismatch.py"
