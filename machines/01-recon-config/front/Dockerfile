FROM nginx:1.27-alpine

RUN apk add --no-cache openssl tar

COPY nginx.conf /etc/nginx/nginx.conf
COPY html/ /srv/www/

# --- WSTG-CONF-03: sensitive file extensions handled as plain text -------------
RUN set -eux; \
    mkdir -p /etc/nginx/tls /srv/www/files /srv/www/uploads /srv/www/secret \
             /srv/www/backup /srv/www/static /srv/www/.git; \
    printf 'DB_HOST=db\nDB_USER=portal\nDB_PASSWORD=Sup3rS3cretPortalPW\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nSTRIPE_SECRET=sk_live_51H8xQ2eZvKYlo2Cfake\n' > /srv/www/.env; \
    printf '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://git.internal.example/acme/portal.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[user]\n\tname = devops\n\temail = devops@acme.internal\n' > /srv/www/.git/config; \
    printf 'HEAD ref: refs/heads/main\n' > /srv/www/.git/HEAD; \
    printf '<?php\n$db_host = "db";\n$db_user = "portal";\n$db_pass = "Sup3rS3cretPortalPW";\n$admin_hash = "5f4dcc3b5aa765d61d8327deb882cf99";\n?>\n' > /srv/www/config.php.bak; \
    printf '<?php\n// legacy include, never executed by this vhost\n$secret = "Sup3rS3cretPortalPW";\n' > /srv/www/db.inc; \
    printf '-- portal dump 2019-04-11\nCREATE TABLE users (id int, email text, password_md5 text);\nINSERT INTO users VALUES (1,'"'"'admin@acme.internal'"'"','"'"'5f4dcc3b5aa765d61d8327deb882cf99'"'"');\n' > /srv/www/db.sql; \
    printf '<?php define("LEGACY", true); // $Id: index.php 412 2019-04-11 devops $\n' > /srv/www/index.php~; \
    printf 'server {\n  listen 8080;\n  root /var/www/old-admin;\n}\n' > /srv/www/admin.bak; \
    printf '<?php define("DB_PASSWORD", "Sup3rS3cretPortalPW");\n' > /srv/www/wp-config.php.save; \
    printf 'Bud1\x00\x00\x00\x10\x00\x00\x00\x08secretconfig.iniIlocblob\x00\x00\x00\x10backupIlocblob\x00\x00\x00\x10filesIlocblob\n' > /srv/www/.DS_Store; \
    printf 'User-agent: *\nDisallow: /admin-backup/\n' > /srv/www/admin-backup-robots.txt; \
    mkdir -p /srv/www/admin-backup; \
    printf 'legacy admin console, decommissioned 2021\nlogin: admin / admin\n' > /srv/www/admin-backup/README.txt

# --- WSTG-INFO-03: metafiles --------------------------------------------------
RUN set -eux; \
    printf '<?xml version="1.0"?>\n<cross-domain-policy>\n  <allow-access-from domain="*" to-ports="*" />\n  <site-control permitted-cross-domain-policies="all"/>\n</cross-domain-policy>\n' > /srv/www/crossdomain.xml; \
    printf '<?xml version="1.0"?>\n<access-policy>\n  <cross-domain-access>\n    <policy>\n      <allow-from http-request-headers="*"><domain uri="*"/></allow-from>\n      <grant-to><resource path="/" include-subpaths="true"/></grant-to>\n    </policy>\n  </cross-domain-access>\n</access-policy>\n' > /srv/www/clientaccesspolicy.xml; \
    mkdir -p /srv/www/.well-known; \
    printf 'Contact: mailto:security@acme.internal\nExpires: 2019-01-01T00:00:00.000Z\nPreferred-Languages: en\nCanonical: https://portal.lab.test/.well-known/security.txt\n\n# stale: internal wiki http://wiki.acme.internal/security\n# staging host: https://staging-portal.acme.internal\n' > /srv/www/.well-known/security.txt; \
    printf '/* TEAM */\nDev: devops@acme.internal\nBackend: Flask + PostgreSQL\nHost: 10.20.30.41 (internal)\n' > /srv/www/humans.txt

# --- WSTG-CONF-13 / CONF-09: alias-traversal target and weak permissions -------
RUN set -eux; \
    printf 'WSTG-M01{path_confusion_and_alias_traversal}\n' > /srv/www/secret/flag.txt; \
    printf '[database]\nhost=db\nuser=portal\npassword=Sup3rS3cretPortalPW\n' > /srv/www/secret/config.ini; \
    printf 'WSTG-M01-STATIC-ASSET\n' > /srv/www/static/app.css; \
    tar czf /srv/www/backup/site-2019.tar.gz -C /srv/www secret index.html .env; \
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -subj "/CN=portal.lab.test/O=WSTG Range M01" \
      -keyout /etc/nginx/tls/portal.key -out /etc/nginx/tls/portal.crt 2>/dev/null; \
    chmod 0777 /srv/www/files /srv/www/uploads; \
    chmod 0644 /srv/www/secret/config.ini /srv/www/.env /srv/www/secret/flag.txt; \
    chown -R nginx:nginx /srv/www

EXPOSE 80 443 8080