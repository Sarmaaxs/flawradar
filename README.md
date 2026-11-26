# FlawRadar

A web security checker for developers developed by Sarem Menur. Enter a website address and FlawRadar reports on its TLS setup, response headers, cookies, DNS records and a few well-known files, then gives you the configuration to fix what it found. It scans from fixed IP addresses that it publishes, so you can allow-list them in a firewall or WAF.

- 29 checks in 7 groups, each with an explanation and a fix for nginx, Apache or Express where one applies
- Bounded multi-page crawl (home + a few same-origin paths) so security headers only set on other routes are not missed
- A public scanner-address page for firewall allow-listing
- Deep scan (exposed `.git`, `.env`, backups, directory listings, HTTP methods) that only runs after the site owner proves control, by a file or a DNS record
- Optional **allow record** (`flawradar-allow=1` as DNS TXT at `_flawradar.<host>` or a file at `/.well-known/flawradar-allow.txt`) raises the per-host rate limit so owners who want scans are not treated as noise
- Reports with a score, grade, history against the previous scan, and downloadable server config
- Source code check: drop a folder, files or a .zip on `/source` and line rules plus file checks look for hard-coded secrets, SQL injection, XSS, shell injection, weak crypto, turned-off TLS checks and risky config. Known dependency CVEs are looked up via OSV when a lockfile is present. The source engine runs server-side: selected files are uploaded over HTTPS and analyzed in memory, while raw source contents are not intentionally persisted. Detection rules are not shipped as browser assets. The `/api/source` endpoints are used by the hosted page and local deployments.
- Domain intelligence at `/intel`: an owner-verified relationship map of public DNS, certificate names, subdomains, public pages, endpoint references, technologies and version-linked advisories
- No dependencies. Node's standard library and its built-in SQLite module

## Requirements

Node.js 22.13 or newer. Nothing to install.

## Run it

```sh
cp .env.example .env     # then edit it
npm start
```

Open http://localhost:3000.

```sh
npm test                 # unit and integration tests
```

With Docker:

```sh
docker build -t flawradar .
docker run -p 3000:3000 -v flawradar-data:/data --env-file .env flawradar
```

## Settings

All settings are environment variables (or lines in `.env`). See `.env.example` for the full list.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT`, `HOST` | `3000`, `127.0.0.1` | Where the web server listens |
| `FLAWRADAR_BASE_URL` | `http://localhost:PORT` | Public address of this instance, used in the user agent |
| `FLAWRADAR_PUBLIC_IPS` | none | Addresses scans leave from. Shown on the Whitelist page |
| `FLAWRADAR_EGRESS_IP` | none | Bind outgoing connections to this local address |
| `FLAWRADAR_CONTACT` | none | Abuse contact shown on the Whitelist page |
| `FLAWRADAR_TRUST_PROXY` | `0` | Read the client address from `X-Forwarded-For` |
| `FLAWRADAR_SCANS_PER_HOUR` | `12` | Scans per visitor per hour |
| `FLAWRADAR_SCANS_PER_HOST_PER_HOUR` | `6` | Scans per target host per hour |
| `FLAWRADAR_MAX_CONCURRENT` | `4` | Scans running at once. More wait in a queue |
| `FLAWRADAR_RETENTION_DAYS` | `30` | Reports are deleted after this many days |
| `FLAWRADAR_SOURCE_PER_HOUR` | `20` | Source code checks per visitor per hour |
| `FLAWRADAR_BLOCKED_HOSTS` | none | Hosts whose owners asked to be excluded (also covers subdomains) |
| `FLAWRADAR_LEGAL_ENTITY`, `_ADDRESS`, `_EMAIL`, `_LAW`, `_ARBITRATION`, `_HOSTING`, `_LOG_RETENTION` | none | Filled into the Terms, Acceptable Use and Privacy pages |
| `FLAWRADAR_SMTP_HOST`, `_PORT`, `_USER`, `_PASS`, `_FROM` | none | Mail server. Setting a host switches watches on |
| `FLAWRADAR_WATCH_INTERVAL_HOURS` | `24` | How often a watched site is rescanned |
| `FLAWRADAR_MAX_WATCHES_PER_EMAIL`, `FLAWRADAR_WATCH_SIGNUPS_PER_HOUR` | `5`, `6` | Limits for watch sign-ups |
| `FLAWRADAR_BACKUP_DIR`, `_KEEP`, `_INTERVAL_HOURS` | off, `7`, `24` | Automatic database copies. The Docker image sets `/data/backups` |
| `FLAWRADAR_DATA_DIR` | `./data` | Where `flawradar.db` is kept |
| `FLAWRADAR_ALLOW_PRIVATE` | off | Development only. Allows private addresses and custom ports |

### Publishing real scanner IPs

The whitelist feature is only useful if the addresses are true. Run FlawRadar on a host with a fixed public address (or a small set), put those in `FLAWRADAR_PUBLIC_IPS`, and make sure outgoing scan traffic really leaves from them. If the machine has several addresses, set `FLAWRADAR_EGRESS_IP` so connections are bound to the published one. Check it from outside: scan a server you control and read the source address in its access log.

If the host sits behind NAT or a cloud gateway, publish the gateway's public address, not the machine's private one.

### Behind a reverse proxy

Put nginx or Caddy in front for HTTPS and set `FLAWRADAR_TRUST_PROXY=1` so rate limits use the visitor's address. Only do this when the proxy is the only thing that can reach the app, because the header is otherwise easy to fake. Set `FLAWRADAR_BASE_URL` to the public https address and the app will send HSTS.

## Before you go public

```sh
npm run check
```

lists what still needs doing: real scanner IPs, the legal details, the contact address, the proxy setting, mail and backups. It exits with code 1 while anything marked FIX is open, and the same list is printed every time the server starts. [DEPLOY.md](DEPLOY.md) walks through it step by step.

## Watches

A visitor who has [proved control of a site](/verify) can ask for a watch: FlawRadar rescans it every day and emails when the grade gets worse (or the score falls by 10 points). The email address is confirmed by a link, every email has a link that stops the watch, and taking the ownership proof off the site stops it too. It needs `FLAWRADAR_SMTP_HOST`; without it the Watch page says so. The mail client is in `server/mail.js` (about 100 lines, TLS and STARTTLS, no dependencies) and the scheduler is in `server/watch.js`.

## Deleting a report, printing, backups

- The browser that started a scan keeps a secret in its local storage and gets a **Delete this report** button. Only a hash of the secret is stored on the server, so a report link alone cannot delete anything.
- **Print or save as PDF** on the report page uses the browser's print dialog, with a print stylesheet that hides the controls and spells out links.
- `FLAWRADAR_BACKUP_DIR` turns on copies of the database (SQLite `VACUUM INTO`, safe while running), `FLAWRADAR_BACKUP_KEEP` of them are kept. `npm run backup` makes one now. `/api/health` returns 503 when the database does not answer and shows the time of the last backup, so an uptime monitor can watch it.
- `.github/workflows/test.yml` runs the tests on every push.

### Safety of the scanner itself

A tool that makes requests to addresses chosen by strangers can be turned against its own host. FlawRadar handles that in several places:

- Host names are validated. IP literals, internal suffixes (`.local`, `.internal`) and custom ports are refused.
- Every name is resolved and every address checked against private, loopback, link-local, multicast and other reserved ranges before connecting.
- The connection is then pinned to the address that was checked, so DNS rebinding cannot swap in another one between the check and the connect.
- Redirects are followed by hand, at most five, and each hop goes through the same checks.
- Responses are size-capped and time-limited.
- Per-visitor and per-host rate limits, a concurrency cap and a queue limit.
- Deep probes require proof of control, checked again at the start of every deep scan.

The web interface is built without `innerHTML`, and the site serves a strict Content-Security-Policy with no inline scripts or styles.

### The API

| Method and path | Purpose |
| --- | --- |
| `POST /api/scans` | Body `{"url": "example.com", "deep": false}`. Returns `202` with `{id}` |
| `GET /api/scans/:id` | Status, progress and, when done, the result |
| `GET /api/scans/:id/fix?server=nginx` | Download fixes as config (`nginx`, `apache`, `express`) |
| `POST /api/verify` | Body `{"host": "example.com"}`. Returns the proof value |
| `POST /api/verify/check` | Checks whether the proof is in place |
| `POST /api/source` | Body `{"files": [{"path": "src/a.js", "content": "..."}]}`. Returns findings, nothing stored |
| `POST /api/source/zip` | Body is the raw .zip, `Content-Type: application/zip` |
| `POST /api/intelligence` | Owner-verified domain relationship map and security findings |
| `POST /api/watch` | Body `{"url", "email", "terms"}`. Starts a watch; a confirmation link is emailed |
| `DELETE /api/scans/:id` | Header `X-FlawRadar-Delete` with the secret returned when the scan was created |
| `GET /api/scanner` | Published scanner addresses, terms version and required public legal metadata |
| `GET /api/health` | Liveness |

## Source code scanning

The source checker analyzes selected files on the server after upload over HTTPS. Files are processed in memory and raw source contents are not intentionally persisted. The detection engine is not sent as browser JavaScript. Findings include severity, a short explanation and a remediation direction; secret values are masked. Dependency advisories are best-effort and depend on the package ecosystem and version data available in the supplied manifests.

Uploads are bounded by file count, per-file size, total text size and ZIP expansion limits. Generated files and common dependency folders are skipped. Do not upload code you are not authorized to share with the service.

## Domain intelligence

The `/intel` page requires proof of control through DNS TXT or a well-known file. It maps the submitted host using public DNS, Certificate Transparency, a public web archive, robots.txt and sitemap metadata, same-origin pages, forms and statically referenced API paths. It fingerprints visible technologies and correlates exact version evidence with OSV or NVD advisories. CVEs are enriched with CVSS, EPSS and CISA KEV context when available.

Discovered subdomains are shown as relationships and are DNS-resolved only; the service does not automatically send HTTP requests to every discovered subdomain. The page inventory prioritizes linked, sitemap-listed and common authentication or administration entry points, while respecting robots.txt exclusions. It does not submit forms, attempt logins, brute-force paths, bypass access controls or run exploits. A historical URL, robots entry or possible dangling CNAME is a lead for an authorized owner to verify, not proof of a current vulnerability.

## Limits

- It checks the home page plus a few same-origin paths. Headers set only on deep or unlinked paths may still be missed.
- It reads policies as written; it does not run the page, so it cannot tell whether a CSP breaks the site.
- DKIM cannot be checked from outside.
- The scan queue and rate limiter are in memory, so this is built for one process. Reports survive restarts, in-flight scans do not. Domain intelligence is request-scoped and is not saved as a public report.
- Old TLS probing depends on the local OpenSSL build. When it cannot tell, the check says so instead of passing silently.

## Adding a check

Add an object to `CHECKS` in `server/scanner/checks.js` with an `id`, `category`, `title`, `severity`, `why`, `ref` and a `run(ctx)` function that returns `pass`, `fail`, `warn`, `info` or `skip`. If it needs data the scan does not collect yet, collect it in `server/scanner/scan.js`. Add a test in `test/checks.test.js`.