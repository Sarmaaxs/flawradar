# FlawRadar

A web security checker for developers developed by Sarem Menur. Enter a website address and FlawRadar reports on its TLS setup, response headers, cookies, DNS records and a few well-known files, then gives you the configuration to fix what it found. It scans from fixed IP addresses that it publishes, so you can allow-list them in a firewall or WAF.

- 29 checks in 7 groups, each with an explanation and a fix for nginx, Apache or Express where one applies
- Bounded multi-page crawl (home + a few same-origin paths) so security headers only set on other routes are not missed
- Scanner IP and user agent page with ready-made rules for nginx, ModSecurity, fail2ban, ufw and Cloudflare
- Deep scan (exposed `.git`, `.env`, backups, directory listings, HTTP methods) that only runs after the site owner proves control, by a file or a DNS record
- Optional **allow record** (`flawradar-allow=1` as DNS TXT at `_flawradar.<host>` or a file at `/.well-known/flawradar-allow.txt`) raises the per-host rate limit so owners who want scans are not treated as noise
- Reports with a score, grade, history against the previous scan, and downloadable server config
- Source code check: drop a folder, files or a .zip on `/source` and line rules plus file checks look for hard-coded secrets, SQL injection, XSS, shell injection, weak crypto, turned-off TLS checks and risky config. Known dependency CVEs are looked up via OSV when a lockfile is present. Code is analysed in memory and never stored
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
| `FLAWRADAR_DATA_DIR` | `./data` | Where `flawradar.db` is kept |
| `FLAWRADAR_ALLOW_PRIVATE` | off | Development only. Allows private addresses and custom ports |

### Publishing real scanner IPs

The whitelist feature is only useful if the addresses are true. Run FlawRadar on a host with a fixed public address (or a small set), put those in `FLAWRADAR_PUBLIC_IPS`, and make sure outgoing scan traffic really leaves from them. If the machine has several addresses, set `FLAWRADAR_EGRESS_IP` so connections are bound to the published one. Check it from outside: scan a server you control and read the source address in its access log.

If the host sits behind NAT or a cloud gateway, publish the gateway's public address, not the machine's private one.

### Behind a reverse proxy

Put nginx or Caddy in front for HTTPS and set `FLAWRADAR_TRUST_PROXY=1` so rate limits use the visitor's address. Only do this when the proxy is the only thing that can reach the app, because the header is otherwise easy to fake. Set `FLAWRADAR_BASE_URL` to the public https address and the app will send HSTS.

## How it works

```
server/
  index.js          starts the server, purges old reports
  app.js            routing, static files, API, security headers
  scans.js          scan queue and concurrency limit
  verify.js         ownership proof for deep scans
  db.js             SQLite storage (node:sqlite)
  ratelimit.js      sliding window limiter
  source/
    rules.js        the line rules and file checks, with explanations and fixes
    analyze.js      runs the rules over uploaded files, masks secrets
    filechecks.js   .env, Dockerfile, package.json, requirements.txt checks
    zip.js          minimal zip reader with zip-bomb limits (in memory, nothing extracted)
    paths.js        which files are read, and path cleaning
  scanner/
    net.js          target parsing, private-address rules, DNS resolution
    fetcher.js      HTTP client, pins the connection to a checked address
    tls.js          handshake, certificate details, legacy protocol probe
    dnsinfo.js      SPF, DMARC, CAA, MX lookups
    html.js         extracts scripts, styles, frames and forms from HTML
    checks.js       the checks and their fixes
    deep.js         exposed-file probes
    scan.js         runs a scan and collects the data the checks need
    score.js        scoring and grade caps
    fixes.js        bundles fixes into a server config file
public/             the web pages, plain HTML with small custom elements
test/               unit and integration tests
```

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
| `GET /api/source/rules` | The rule list and upload limits |
| `GET /api/scanner` | Published addresses, user agent, contact |
| `GET /api/checks` | The list of checks with explanations |
| `GET /api/health` | Liveness |

## Source code scanning

The rules in `server/source/rules.js` match one line at a time. They find common mistakes and do not follow data from a request into a database call, so multi-line and cross-file bugs, and logic errors such as missing permission checks, are not found. Each rule has a confidence level because some matches are lookalikes.

Known vulnerabilities in dependencies are looked up via the OSV API when a `package-lock.json` or pinned `requirements.txt` is present (and, less precisely, from `package.json` version ranges if no lockfile exists). The lookup is best-effort: if OSV is unreachable the scan still finishes and a notice is shown. Coverage is not complete — also run `npm audit`, `pip-audit` or `osv-scanner` in CI.

Uploads are limited to 3000 files, 512 KB per file, 30 MB of text and a 10 MB zip (see `server/config.js`). Folders like `node_modules`, `.git`, `vendor`, `dist` and `build` are skipped, and lines over 1000 characters (minified code) are skipped. Zips are read in memory with a hard cap on how far any entry may inflate.

To add a rule, add an object to `RULES` with an `id`, `title`, `severity`, `confidence`, `pattern`, `why`, `fix` and optionally `exts` and a `filter` function, then add a positive and a negative case to `test/source.test.js`.

## Limits

- It checks the home page plus a few same-origin paths. Headers set only on deep or unlinked paths may still be missed.
- It reads policies as written; it does not run the page, so it cannot tell whether a CSP breaks the site.
- DKIM cannot be checked from outside.
- The scan queue and rate limiter are in memory, so this is built for one process. Reports survive restarts, in-flight scans do not.
- Old TLS probing depends on the local OpenSSL build. When it cannot tell, the check says so instead of passing silently.

## Adding a check

Add an object to `CHECKS` in `server/scanner/checks.js` with an `id`, `category`, `title`, `severity`, `why`, `ref` and a `run(ctx)` function that returns `pass`, `fail`, `warn`, `info` or `skip`. If it needs data the scan does not collect yet, collect it in `server/scanner/scan.js`. Add a test in `test/checks.test.js`.