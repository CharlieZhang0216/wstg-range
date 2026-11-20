# WSTG coverage matrix

Upstream: `https://github.com/OWASP/wstg` @ `5bd51b35d4d5`

**132/132 test IDs** - **145/145 test documents** - 10 machines

Excluded as removed upstream: WSTG-CLNT-08, WSTG-CONF-08

| Machine | ID | Name | Docs | Surface | Severity | Probe |
|---|---|---|---|---|---|---|
| 01-recon-config | `WSTG-CONF-01` | Network Infrastructure Configuration | 1 | `TCP :8179 (Redis), published port inventory` | high | `conf_01` |
| 01-recon-config | `WSTG-CONF-02` | Application Platform Configuration | 1 | `GET :8105/ , :8105/samples/ , :8100/backup/` | medium | `conf_02` |
| 01-recon-config | `WSTG-CONF-03` | File Extensions Handling for Sensitive Information | 1 | `GET /.env /config.php.bak /db.inc /db.sql, :8105/phpinfo.php` | high | `conf_03` |
| 01-recon-config | `WSTG-CONF-04` | Review Old Backup and Unreferenced Files for Sensitive Information | 1 | `GET /backup/site-2019.tar.gz /index.php~ /.DS_Store /admin-backup/README.txt` | high | `conf_04` |
| 01-recon-config | `WSTG-CONF-05` | Enumerate Infrastructure and Application Admin Interfaces | 1 | `GET :8106/ :8105/server-status :8105/server-info :8107/nginx_status` | high | `conf_05` |
| 01-recon-config | `WSTG-CONF-06` | HTTP Methods | 1 | `TRACE :8105/, OPTIONS :8105/dav/, PUT+DELETE :8100/files/` | high | `conf_06` |
| 01-recon-config | `WSTG-CONF-07` | HTTP Strict Transport Security | 1 | `GET https://127.0.0.1:8143/ and http://127.0.0.1:8100/` | medium | `conf_07` |
| 01-recon-config | `WSTG-CONF-09` | File Permissions | 1 | `GET /debug/files, PUT /files/` | high | `conf_09` |
| 01-recon-config | `WSTG-CONF-10` | Subdomain Takeover | 1 | `DNS dangling.lab.test / abandoned.lab.test, GET+POST :8180` | high | `conf_10` |
| 01-recon-config | `WSTG-CONF-11` | Cloud Storage (degraded) | 1 | `GET :8190/acme-public-assets/customers.csv (anonymous)` | critical | `conf_11` |
| 01-recon-config | `WSTG-CONF-12` | Content Security Policy | 1 | `GET /search?q=x vs GET /reports` | medium | `conf_12` |
| 01-recon-config | `WSTG-CONF-13` | Path Confusion | 1 | `GET /static../secret/flag.txt, GET /admin/users vs /apiadmin/users` | high | `conf_13` |
| 01-recon-config | `WSTG-CONF-14` | Additional Browser Security Controls | 1 | `GET / and /search` | medium | `conf_14` |
| 01-recon-config | `WSTG-CONF-15` | Feature Flag Security Bypass | 1 | `GET /flags.json, GET /feature-preview with ff_new_admin cookie` | high | `conf_15` |
| 01-recon-config | `WSTG-CONF-16` | Web Cache Poisoning | 1 | `GET :8160/cached/page with X-Forwarded-Host, then without` | high | `conf_16` |
| 01-recon-config | `WSTG-INFO-01` | Conduct Search Engine Reconnaissance for Information Leakage (degraded) | 1 | `GET :8185/search?q=password` | medium | `info_01` |
| 01-recon-config | `WSTG-INFO-02` | Fingerprint Web Server | 1 | `GET / and GET :8105/` | info | `info_02` |
| 01-recon-config | `WSTG-INFO-03` | Review Webserver Metafiles for Information Leakage | 1 | `GET /robots.txt /sitemap.xml /crossdomain.xml /clientaccesspolicy.xml /.well-known/security.txt /humans.txt` | low | `info_03` |
| 01-recon-config | `WSTG-INFO-04` | Attack Surface Identification | 1 | `TCP scan 8100-8199 + GET /sitemap.xml` | info | `info_04` |
| 01-recon-config | `WSTG-INFO-05` | Review Web Page Content for Information Leakage | 1 | `GET /` | high | `info_05` |
| 01-recon-config | `WSTG-INFO-06` | Identify Application Entry Points | 1 | `GET /search?q=, POST /contact` | info | `info_06` |
| 01-recon-config | `WSTG-INFO-07` | Map Execution Paths Through Application | 1 | `crawl / -> /reports -> /reports/quarterly -> /reports/quarterly/export` | info | `info_07` |
| 01-recon-config | `WSTG-INFO-08` | Fingerprint Web Application Framework | 1 | `GET /boom, GET /no-such-page` | low | `info_08` |
| 01-recon-config | `WSTG-INFO-09` | Fingerprint Web Application | 1 | `GET / (meta generator), GET /CHANGELOG.txt` | info | `info_09` |
| 01-recon-config | `WSTG-INFO-10` | Map Application Architecture | 1 | `GET / , :8160/cached/page , /api/internal/users` | info | `info_10` |
| 02-identity-authn | `WSTG-ATHN-01` | Credentials Transported over an Encrypted Channel | 1 | `GET /login, POST /login over http://127.0.0.1:8200` | high | `athn_01` |
| 02-identity-authn | `WSTG-ATHN-02` | Default Credentials | 1 | `POST /login` | critical | `athn_02` |
| 02-identity-authn | `WSTG-ATHN-03` | Weak Lock Out Mechanism | 1 | `POST /login with X-Forwarded-For / reset_counter=1` | high | `athn_03` |
| 02-identity-authn | `WSTG-ATHN-04` | Bypassing Authentication Schema | 1 | `GET /account?authenticated=true (or Cookie authenticated=true)` | critical | `athn_04` |
| 02-identity-authn | `WSTG-ATHN-05` | Vulnerable Remember Password | 1 | `POST /login remember=1, GET /account with remember_me cookie` | high | `athn_05` |
| 02-identity-authn | `WSTG-ATHN-06` | Browser Cache Weaknesses | 1 | `GET /account (authenticated)` | medium | `athn_06` |
| 02-identity-authn | `WSTG-ATHN-07` | Weak Authentication Methods | 1 | `GET /basic/profile, GET /login?username=&password=` | high | `athn_07` |
| 02-identity-authn | `WSTG-ATHN-08` | Weak Security Question Answer | 1 | `GET /recover/questions, POST /recover/answer` | high | `athn_08` |
| 02-identity-authn | `WSTG-ATHN-09` | Weak Password Change or Reset Functionalities | 1 | `POST /reset/request (Host header), POST /reset/confirm` | critical | `athn_09` |
| 02-identity-authn | `WSTG-ATHN-10` | Weaker Authentication in Alternative Channel | 1 | `POST /mobile/login (Basic), GET /mobile/profile` | high | `athn_10` |
| 02-identity-authn | `WSTG-ATHN-11` | Multi-Factor Authentication (MFA) | 1 | `POST /login, GET /mfa/dashboard, POST /mfa/verify` | high | `athn_11` |
| 02-identity-authn | `WSTG-ATHN-12` | SAML Authentication | 1 | `POST /saml/acs (SAMLResponse), Keycloak IdP /realms/lab/protocol/saml` | critical | `athn_12` |
| 02-identity-authn | `WSTG-ATHN-13` | Passkeys and WebAuthn | 1 | `POST /webauthn/register|login/options|complete, GET /webauthn/credentials` | high | `athn_13` |
| 02-identity-authn | `WSTG-ATHN-14` | OpenID Connect Relying Party | 1 | `GET /oidc/login?redirect_uri=, GET /oidc/callback?id_token=` | critical | `athn_14` |
| 02-identity-authn | `WSTG-IDNT-01` | Role Definitions | 1 | `GET /api/roles, POST /register (role=superadmin), GET /admin/panel` | high | `idnt_01` |
| 02-identity-authn | `WSTG-IDNT-02` | User Registration Process | 1 | `POST /register, POST /login, GET /api/users?username=` | medium | `idnt_02` |
| 02-identity-authn | `WSTG-IDNT-03` | Account Provisioning Process | 1 | `POST /api/provision/bulk, GET /api/users/<id>` | high | `idnt_03` |
| 02-identity-authn | `WSTG-IDNT-04` | Account Enumeration and Guessable User Account | 1 | `POST /login, POST /register, POST /reset/request` | medium | `idnt_04` |
| 02-identity-authn | `WSTG-IDNT-05` | Weak or Unenforced Username Policy | 1 | `POST /register` | low | `idnt_05` |
| 03-authz-session | `WSTG-ATHZ-01` | Directory Traversal and File Include | 1 | `GET /files/download?name=, GET /files/fetch?path=` | high | `athz_01` |
| 03-authz-session | `WSTG-ATHZ-02` | Bypassing Authorization Schema | 1 | `GET /admin/users, POST /admin/announce, GET vs POST /admin/export, GET /admin/panel + POST /admin/settings` | high | `athz_02` |
| 03-authz-session | `WSTG-ATHZ-03` | Privilege Escalation | 1 | `POST /profile/update (role parameter)` | critical | `athz_03` |
| 03-authz-session | `WSTG-ATHZ-04` | Insecure Direct Object References | 1 | `GET/POST /documents/<id>, GET /orders/<id>, GET /api/users -> GET /messages/<uuid>` | high | `athz_04` |
| 03-authz-session | `WSTG-ATHZ-05` | OAuth Weaknesses / OAuth Authorization Server Weaknesses / OAuth Client Weaknesses | 3 | `:8310/oauth/authorize + /oauth/token (AS), /oauth/login + /oauth/callback + /redirect + /oauth/connected (client)` | critical | `athz_05` |
| 03-authz-session | `WSTG-SESS-01` | Session Management Schema | 1 | `Set-Cookie SID on GET / and POST /login` | critical | `sess_01` |
| 03-authz-session | `WSTG-SESS-02` | Cookies Attributes | 1 | `Set-Cookie SID (all responses)` | medium | `sess_02` |
| 03-authz-session | `WSTG-SESS-03` | Session Fixation | 1 | `GET / with attacker-chosen SID, then POST /login` | high | `sess_03` |
| 03-authz-session | `WSTG-SESS-04` | Exposed Session Variables | 1 | `GET /api/me?sid=, GET /dashboard?sid= (hidden field + third-party img), Referer to :8320/pixel` | high | `sess_04` |
| 03-authz-session | `WSTG-SESS-05` | Cross Site Request Forgery | 1 | `POST /transfer (cookie-only auth), :8320/csrf attack page` | high | `sess_05` |
| 03-authz-session | `WSTG-SESS-06` | Logout Functionality | 1 | `POST /logout, then GET /api/me with the old SID` | medium | `sess_06` |
| 03-authz-session | `WSTG-SESS-07` | Session Timeout | 1 | `GET /api/session-policy, POST /debug/age-session, GET /api/me` | medium | `sess_07` |
| 03-authz-session | `WSTG-SESS-08` | Session Puzzling | 1 | `POST /reset/request -> POST /reset/confirm -> GET /admin` | critical | `sess_08` |
| 03-authz-session | `WSTG-SESS-09` | Session Hijacking | 1 | `GET /api/me + /documents/1 with a stolen SID from a different client context` | critical | `sess_09` |
| 03-authz-session | `WSTG-SESS-10` | JSON Web Tokens | 1 | `POST /api/token, GET /api/v2/me + /api/v2/admin (Bearer JWT)` | critical | `sess_10` |
| 03-authz-session | `WSTG-SESS-11` | Concurrent Sessions | 1 | `5x POST /login, POST /account/password, GET /api/me on every session` | medium | `sess_11` |
| 04-injection-datastore | `WSTG-INJT-05` | SQL Injection / Oracle / MySQL / SQL Server / PostgreSQL / MS Access / NoSQL Injection / ORM Injection / Client-side (degraded) | 9 | `GET /mysql/* /pg/* /mssql/* /access/products /pls/lab/WEB_USERS.* /nosql/* /orm/users /clientsql/` | critical | `injt_05` |
| 04-injection-datastore | `WSTG-INJT-06` | LDAP Injection | 1 | `GET /ldap/login?uid=&password=` | high | `injt_06` |
| 04-injection-datastore | `WSTG-INJT-07` | XML Injection | 1 | `POST /xml/order (form), POST /xml/parse (raw XML)` | high | `injt_07` |
| 04-injection-datastore | `WSTG-INJT-09` | XPath Injection | 1 | `GET /xpath/login?user=&pass=` | high | `injt_09` |
| 04-injection-datastore | `WSTG-INJT-26` | JSON Parser Differentials | 1 | `POST :8401/json/transfer -> app /json/backend` | high | `injt_26` |
| 05-injection-xss-code | `WSTG-INJT-01` | Reflected Cross Site Scripting | 1 | `GET/POST :8500/search?q=` | high | `injt_01` |
| 05-injection-xss-code | `WSTG-INJT-02` | Stored Cross Site Scripting | 1 | `POST :8500/guestbook (author=, comment=) then GET /guestbook; POST /profile (bio=) then GET /profile` | high | `injt_02` |
| 05-injection-xss-code | `WSTG-INJT-03` | HTTP Verb Tampering | 1 | `PUT/PATCH/HEAD/FOO :8500/admin/panel and /admin/users/delete; POST :8500/search vs GET` | high | `injt_03` |
| 05-injection-xss-code | `WSTG-INJT-04` | HTTP Parameter Pollution | 1 | `GET :8500/hpp/admin?role=user&role=admin; POST :8500/hpp/transfer (action=view&action=transfer&amount=1&amount=500)` | high | `injt_04` |
| 05-injection-xss-code | `WSTG-INJT-08` | SSI Injection | 1 | `GET :8505/cgi-bin/greet.cgi?name=<!--#exec cmd="id"--> then GET the returned /pages/*.shtml` | critical | `injt_08` |
| 05-injection-xss-code | `WSTG-INJT-11` | Code Injection / File Inclusion | 2 | `GET :8510/eval.php?expr=, /call.php?fn=&arg=, /page.php?page= (traversal, php://filter, access log, http://rfi/shell.txt)` | critical | `injt_11` |
| 05-injection-xss-code | `WSTG-INJT-12` | Command Injection | 1 | `GET :8500/net/ping?host=, GET :8500/net/lookup?host= (blind), GET :8510/cmd.php?host=` | critical | `injt_12` |
| 05-injection-xss-code | `WSTG-INJT-18` | Server-side Template Injection | 1 | `GET :8500/tpl/jinja?name= and GET :8500/tpl/mako?name=` | critical | `injt_18` |
| 05-injection-xss-code | `WSTG-INJT-22` | Prototype Pollution | 1 | `POST :8520/settings {"__proto__":{...}} then GET /admin, GET /profile, POST /render on new connections` | high | `injt_22` |
| 05-injection-xss-code | `WSTG-INJT-25` | Unicode Normalization and Case Mapping | 1 | `GET :8500/unicode/download?file=, /unicode/whoami?user=, /unicode/search?q=, /unicode/reflect?text=` | high | `injt_25` |
| 06-injection-server-protocol | `WSTG-INJT-10` | IMAP SMTP Injection | 1 | `POST /contact (SMTP), GET /webmail?folder= (IMAP)` | high | `injt_10` |
| 06-injection-server-protocol | `WSTG-INJT-13` | Buffer Overflow / Format String Injection | 2 | `TCP :8613 'OVF <data>' and 'FMT <data>'` | critical | `injt_13` |
| 06-injection-server-protocol | `WSTG-INJT-14` | Incubated Vulnerability | 1 | `POST /incubate/store then POST /incubate/recall -> export worker` | high | `injt_14` |
| 06-injection-server-protocol | `WSTG-INJT-15` | HTTP Response Splitting | 1 | `GET :8615/legacy?lang=` | high | `injt_15` |
| 06-injection-server-protocol | `WSTG-INJT-16` | HTTP Request Smuggling | 1 | `POST :8616 (CL-framing proxy) with obfuscated Transfer-Encoding + innocent GET on same connection` | critical | `injt_16` |
| 06-injection-server-protocol | `WSTG-INJT-17` | Host Header Injection | 1 | `GET /password-reset, /host-echo, /host-cache/page` | high | `injt_17` |
| 06-injection-server-protocol | `WSTG-INJT-19` | Server-Side Request Forgery | 1 | `GET /fetch?url= (http/file/gopher)` | critical | `injt_19` |
| 06-injection-server-protocol | `WSTG-INJT-20` | Mass Assignment | 1 | `POST /api/users then GET /api/admin/flag?user_id=` | high | `injt_20` |
| 06-injection-server-protocol | `WSTG-INJT-21` | CSV Injection (degraded) | 1 | `POST /feedback, GET /export.csv, POST :8620/csv-open` | medium | `injt_21` |
| 06-injection-server-protocol | `WSTG-INJT-23` | Insecure Deserialization | 1 | `GET /pickle?data= (Python) and GET :8605/?data= (PHP POP chain)` | critical | `injt_23` |
| 06-injection-server-protocol | `WSTG-INJT-24` | Server-side URL Redirect | 1 | `GET /redirect?url=` | medium | `injt_24` |
| 06-injection-server-protocol | `WSTG-INJT-27` | Server-side Document Rendering Injection | 1 | `POST :8627/render (headless Chromium)` | high | `injt_27` |
| 06-injection-server-protocol | `WSTG-INJT-28` | Regular Expression Denial of Service | 1 | `GET /validate?username=` | medium | `injt_28` |
| 07-crypto-error | `WSTG-CRYP-01` | Weak Transport Layer Security | 1 | `TLS handshake sweep on :8743 + GET https://127.0.0.1:8743/` | high | `cryp_01` |
| 07-crypto-error | `WSTG-CRYP-02` | Padding Oracle | 1 | `POST /oracle/decrypt, GET /oracle/secret` | critical | `cryp_02` |
| 07-crypto-error | `WSTG-CRYP-03` | Sensitive Information Sent via Unencrypted Channels | 1 | `POST http://127.0.0.1:8700/login, GET /api/account (Basic auth), TCP :8723, https://127.0.0.1:8743/` | high | `cryp_03` |
| 07-crypto-error | `WSTG-CRYP-04` | Weak Cryptographic Primitives | 1 | `GET /users, /ecb/*, /des/secret, /rc4/secret, /legacy/docs, /token` | critical | `cryp_04` |
| 07-crypto-error | `WSTG-ERRH-01` | Improper Error Handling | 1 | `GET /user?id=, POST /api/transfer, GET /api/balance` | high | `errh_01` |
| 07-crypto-error | `WSTG-ERRH-02` | Stack Traces | 1 | `GET :8700/boom (Flask/Werkzeug debug), GET :8705/crash and /parse (Express)` | medium | `errh_02` |
| 08-business-logic | `WSTG-BUSL-01` | Business Logic Data Validation | 1 | `POST /cart/add, POST /checkout, POST /checkout/confirm` | high | `busl_01` |
| 08-business-logic | `WSTG-BUSL-02` | Ability to Forge Requests | 1 | `POST /checkout (lines[].unit_price, shipping, total)` | high | `busl_02` |
| 08-business-logic | `WSTG-BUSL-03` | Integrity Checks | 1 | `POST /order/update + GET /static/checkout.js` | high | `busl_03` |
| 08-business-logic | `WSTG-BUSL-04` | Process Timing | 1 | `POST /cart/coupon (parallel), POST /checkout (purchase_time)` | high | `busl_04` |
| 08-business-logic | `WSTG-BUSL-05` | Number of Times a Function Can Be Used Limits | 1 | `POST /cart/coupon code=WELCOME5` | medium | `busl_05` |
| 08-business-logic | `WSTG-BUSL-06` | Circumvention of Work Flows | 1 | `POST /checkout/confirm, POST /order/ship` | high | `busl_06` |
| 08-business-logic | `WSTG-BUSL-07` | Defenses Against Application Misuse | 1 | `POST /giftcard/redeem (300-request enumeration)` | medium | `busl_07` |
| 08-business-logic | `WSTG-BUSL-08` | Upload of Unexpected File Types | 1 | `POST /account/avatar, GET :8820/<file>` | critical | `busl_08` |
| 08-business-logic | `WSTG-BUSL-09` | Upload of Malicious Files | 1 | `POST /products/import (zip), POST /account/avatar (svg)` | critical | `busl_09` |
| 08-business-logic | `WSTG-BUSL-10` | Payment Functionality | 1 | `POST /payment/create, POST /payment/callback, POST /order/refund` | critical | `busl_10` |
| 08-business-logic | `WSTG-BUSL-11` | Denial of Inventory | 1 | `POST /cart/add (reservations), POST /lab/sweep` | medium | `busl_11` |
| 09-client-side | `WSTG-CLNT-01` | DOM-Based Cross Site Scripting / Self DOM Based Cross Site Scripting | 2 | `GET /dom-xss#<payload>, /dom-xss?name=, /self-xss (and ?csp=1)` | high | `clnt_01` |
| 09-client-side | `WSTG-CLNT-02` | JavaScript Execution | 1 | `GET /js-exec?expr=&cb=, new Function / setTimeout(string) buttons, GET /api/jsonp?callback=` | high | `clnt_02` |
| 09-client-side | `WSTG-CLNT-03` | HTML Injection | 1 | `GET /html-inject?markup=` | medium | `clnt_03` |
| 09-client-side | `WSTG-CLNT-04` | Client-side URL Redirect | 1 | `GET /redirect?next=` | medium | `clnt_04` |
| 09-client-side | `WSTG-CLNT-05` | CSS Injection | 1 | `GET /profile?css=, POST /profile/theme` | medium | `clnt_05` |
| 09-client-side | `WSTG-CLNT-06` | Client-side Resource Manipulation | 1 | `GET /widget?src=&frame=` | high | `clnt_06` |
| 09-client-side | `WSTG-CLNT-07` | Cross Origin Resource Sharing | 1 | `GET /api/cors/reflect, /api/cors/regex, /api/cors/regex2, /api/cors/null, /api/cors/wildcard` | high | `clnt_07` |
| 09-client-side | `WSTG-CLNT-09` | Clickjacking | 1 | `GET /account/settings framed from attacker /clickjack` | medium | `clnt_09` |
| 09-client-side | `WSTG-CLNT-10` | WebSockets | 1 | `WS /ws opened from the attacker origin` | high | `clnt_10` |
| 09-client-side | `WSTG-CLNT-11` | Web Messaging | 1 | `GET /messages framed by the attacker origin, postMessage both directions` | high | `clnt_11` |
| 09-client-side | `WSTG-CLNT-12` | Browser Storage | 1 | `GET /storage?note=, localStorage/sessionStorage/IndexedDB, storage events across tabs` | high | `clnt_12` |
| 09-client-side | `WSTG-CLNT-13` | Cross Site Script Inclusion | 1 | `GET /api/private.js, /api/jsonp?callback=, /api/orders included via <script src> from the attacker origin` | high | `clnt_13` |
| 09-client-side | `WSTG-CLNT-14` | Reverse Tabnabbing | 1 | `GET /links -> attacker /tabnab (target=_blank rel=opener and window.open)` | medium | `clnt_14` |
| 09-client-side | `WSTG-CLNT-15` | Client-side Template Injection | 1 | `GET /template?expr= (AngularJS 1.8.2)` | high | `clnt_15` |
| 09-client-side | `WSTG-CLNT-16` | DOM Clobbering | 1 | `GET /clobber?bio= (naive sanitiser keeps id/name/href)` | high | `clnt_16` |
| 09-client-side | `WSTG-CLNT-18` | Cross-Site Leaks | 1 | `GET /dashboard framed cross-origin (window.length), GET /api/search?q= via <script> load/error events` | medium | `clnt_18` |
| 09-client-side | `WSTG-CLNT-19` | Client-side Path Traversal | 1 | `GET /files?doc=../../api/admin/users` | high | `clnt_19` |
| 09-client-side | `WSTG-CLNT-20` | Service Workers | 1 | `POST /custom/<name>.js then GET /sw-page?sw=/custom/<name>.js` | high | `clnt_20` |
| 09-client-side | `WSTG-CLNT-21` | DNS Rebinding | 1 | `DNS rebind.lab.test (TTL 0) via :8953, Chromium through the :8908 rebinding proxy, http://rebind.lab.test:8902/` | high | `clnt_21` |
| 10-api-wasm | `WSTG-APIT-01` | API Reconnaissance | 1 | `GET /openapi.json /swagger/ /debug/routes /.well-known/api-catalog /app.js, POST /graphql introspection, GET /api/legacy/orders, /v2/orders/{id}` | medium | `apit_01` |
| 10-api-wasm | `WSTG-APIT-02` | API Broken Object Level Authorization | 1 | `GET+PUT /v1/orders/{id}, POST /v1/orders/update (id in body), GET /api/users/{id}/documents, GET+PUT /api/documents/{uuid}` | high | `apit_02` |
| 10-api-wasm | `WSTG-APIT-03` | Excessive Data Exposure | 1 | `GET /api/users, GET /v2/orders/{id}` | high | `apit_03` |
| 10-api-wasm | `WSTG-APIT-04` | API Broken Function Level Authorization | 1 | `GET /api/admin/users, DELETE /v1/orders/{id}, POST /api/users/{id}/role` | critical | `apit_04` |
| 10-api-wasm | `WSTG-APIT-09` | Inbound Webhooks | 1 | `POST /webhooks/provider, GET /api/webhooks/events, mock provider :9020/sample-event` | critical | `apit_09` |
| 10-api-wasm | `WSTG-APIT-10` | gRPC | 1 | `gRPC 127.0.0.1:9010 lab.Inventory (reflection, plaintext h2c)` | high | `apit_10` |
| 10-api-wasm | `WSTG-APIT-99` | GraphQL | 1 | `POST /graphql (introspection, deep nesting, aliased login batch, updateOrderStatus, setUserRole)` | high | `apit_99` |
| 10-api-wasm | `WSTG-WASM-01` | WebAssembly Reconnaissance | 1 | `GET /app.js /license.wasm /telemetry.bin /src/license.c` | medium | `wasm_01` |
