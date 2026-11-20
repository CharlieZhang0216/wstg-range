# M01 - Reconnaissance & Configuration/Deployment Management

> **Intentionally vulnerable training target.** Every weakness here is deliberate.
> For authorised security testing and training only. All ports are published on
> `127.0.0.1`; do not expose this stack to any network you do not control.

Covers **25 WSTG tests**: `WSTG-INFO-01..10` and `WSTG-CONF-01..07, 09..16`.

## Topology

```
                       ┌──────────────┐
   :8100 HTTP ─────────▶│    front     │ nginx/1.27  (server_tokens on, autoindex,
   :8143 HTTPS ────────▶│              │  DAV, alias traversal, slash-less proxy)
   :8107 status ───────▶└──────┬───────┘
                               │ proxy_pass
                        ┌──────▼───────┐        ┌──────────────┐
                        │     app      │───────▶│      db      │ postgres:16
                        │ Flask 3.0.3  │        │ (internal)   │
                        └──────▲───────┘        └──────▲───────┘
   :8160 ──▶ cache (Varnish 7.6, URL-only cache key)    │
   :8106 ──▶ adminer 4.8.1 ────────────────────────────┘
   :8105 ──▶ apache httpd/2.4.65 (autoindex, server-status/info, TRACE, DAV)
   :8153 ──▶ dns CoreDNS 1.11.3, authoritative for lab.test
   :8180 ──▶ saas  (unclaimed-host 404 + /claim, subdomain takeover)
   :8185 ──▶ search (in-range crawler + dorkable index)
   :8190 ──▶ s3 LocalStack 4.0 (public-read bucket with PII)
   :8179 ──▶ redis 7.4 (no auth, published)
```

| Port | Service | Purpose |
|---|---|---|
| 8100 | front | main portal, HTTP |
| 8143 | front | HTTPS vhost, no HSTS |
| 8107 | front | nginx `stub_status` |
| 8105 | apache | legacy vhost, TRACE + DAV + server-status/info |
| 8106 | adminer | exposed DB admin UI |
| 8160 | cache | Varnish, cache-poisoning target |
| 8153 | dns | CoreDNS (TCP+UDP), `lab.test` zone |
| 8179 | redis | unauthenticated datastore |
| 8180 | saas | subdomain-takeover provider |
| 8185 | search | in-range search index |
| 8190 | s3 | S3 API |

`db` sits on an `internal: true` network and is not published.

## Run

```bash
docker compose up --build -d
docker compose ps
../../tools/verify.sh .            # 25 probes, expect 25/25
```

If your Docker injects a host-side proxy from `~/.docker/config.json`, the
compose file already blanks it for builds. To use a real proxy instead:
`export LAB_HTTP_PROXY=http://your-proxy:port`.

## Attack walkthrough

### Information gathering

| ID | How to exercise it |
|---|---|
| INFO-01 | `curl ':8185/search?q=password'` — the index returns `/.env`, `/secret/config.ini`, `/debug/config`. `robots.txt` advertises them. *(in-range index replaces a public engine)* |
| INFO-02 | `curl -I :8100/` → `Server: nginx/1.27.5`; `curl -I :8105/` → `Apache/2.4.65 (Unix)` |
| INFO-03 | `robots.txt`, `sitemap.xml`, `crossdomain.xml` (`domain="*"`), `clientaccesspolicy.xml`, `.well-known/security.txt`, `humans.txt` |
| INFO-04 | port-scan 8100-8199 (11 open) and read `sitemap.xml` (15 paths, several unlinked) |
| INFO-05 | `curl :8100/` — HTML comment holds `portal/Sup3rS3cretPortalPW @ 10.20.30.41`, hidden field `tenant=acme-internal-001`, inline JS holds `ak_live_...` |
| INFO-06 | homepage exposes `GET /search?q=&tenant=&debug=` and `POST /contact` |
| INFO-07 | crawl `/` → `/reports` → `/reports/quarterly` → `/reports/quarterly/export` (data export reachable only by path mapping) |
| INFO-08 | `curl :8100/boom` → 500 Werkzeug/Flask traceback with version |
| INFO-09 | `<meta name="generator" content="AcmePortal 3.2.1 (build 412)">`, `/CHANGELOG.txt`, `X-App-Version` |
| INFO-10 | `Server: nginx` + `Via: ... Varnish/7.6` + `X-Backend: portal-app-01` + `/api/internal/users` → `postgresql@db`: four tiers mapped from outside |

### Configuration and deployment

| ID | How to exercise it |
|---|---|
| CONF-01 | `printf 'INFO\r\n' \| nc 127.0.0.1 8179` → unauthenticated Redis |
| CONF-02 | `:8105/` default "It works!", `:8105/dav/` and `:8100/backup/` directory listings |
| CONF-03 | `/.env`, `/config.php.bak`, `/db.inc`, `/db.sql`, `:8105/phpinfo.php` (PHP source, no handler) |
| CONF-04 | `/backup/site-2019.tar.gz` — a real tarball containing `.env` and `secret/config.ini`; also `/index.php~`, `/.DS_Store`, `/admin-backup/README.txt` |
| CONF-05 | `:8106/` Adminer, `:8105/server-status`, `:8105/server-info`, `:8107/nginx_status`; app login `admin/admin` |
| CONF-06 | `TRACE :8105/` echoes headers; `PUT`/`DELETE` on `:8100/files/` and `:8105/dav/` |
| CONF-07 | `curl -kI :8143/` → no `Strict-Transport-Security`; `:8100/` serves content instead of redirecting |
| CONF-09 | `/debug/files` → uploads `0o777`, `config.ini` `0o644`; anonymous `PUT` into the web root succeeds |
| CONF-10 | `dig @127.0.0.1 -p 8153 dangling.lab.test CNAME` → `unclaimed-saas.lab.test`; `curl -H 'Host: dangling.lab.test' :8180/` → 404 "There isn't a GitHub Pages site here."; `POST :8180/claim` then re-request → your content. `abandoned.lab.test` is NXDOMAIN. |
| CONF-11 | `curl :8190/acme-public-assets/customers.csv` (anonymous) → PII; `?policy` → `Principal: "*"`; `?acl` → `AllUsers`. **Degraded:** LocalStack does not enforce authz for anonymous requests, so the private sibling bucket cannot be shown returning 403. |
| CONF-12 | `/search` sends `script-src 'unsafe-inline' 'unsafe-eval' *`; `/reports` sends no CSP |
| CONF-13 | `curl ':8100/static../secret/flag.txt'` → 200 (alias traversal); `/admin/users` → 403 but `/apiadmin/users` → 200 (slash-less proxy prefix); `merge_slashes off` |
| CONF-14 | no `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-*` |
| CONF-15 | `/flags.json` is public; `/feature-preview` → 403, but `Cookie: ff_new_admin=1` or `X-Feature-Flag: ff_new_admin` → 200 |
| CONF-16 | `curl -H 'X-Forwarded-Host: evil.test' ':8160/cached/page?x=1'` then `curl ':8160/cached/page?x=1'` → `X-Cache: HIT` serving `evil.test` |

## Notes

- `WSTG-CONF-08` (RIA Cross Domain Policy) is **removed upstream** and is not part
  of the coverage denominator. `crossdomain.xml` is still served here because
  `WSTG-INFO-03` covers metafile review.
- Reset the takeover demo with `POST :8180/release {"hostname":"dangling.lab.test"}`.
  The CONF-10 probe does this automatically, so it is idempotent.