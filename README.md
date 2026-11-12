# Wsec

A web security checker for developers. Enter a website address and Wsec reports on its TLS setup, response headers, cookies, DNS records and a few well-known files, then gives you the configuration to fix what it found. It scans from fixed IP addresses that it publishes, so you can allow-list them in a firewall or WAF.

- 29 checks in 7 groups, each with an explanation and a fix for nginx, Apache or Express where one applies
- Scanner IP and user agent page with ready-made rules for nginx, ModSecurity, fail2ban, ufw and Cloudflare
- Deep scan (exposed `.git`, `.env`, backups, directory listings, HTTP methods) that only runs after the site owner proves control, by a file or a DNS record
- Reports with a score, grade, history against the previous scan, and downloadable server config
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
docker build -t wsec .
docker run -p 3000:3000 -v wsec-data:/data --env-file .env wsec
```

## Settings

All settings are environment variables (or lines in `.env`). See `.env.example` for the full list.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT`, `HOST` | `3000`, `127.0.0.1` | Where the web server listens |
| `WSEC_BASE_URL` | `http://localhost:PORT` | Public address of this instance, used in the user agent |
| `WSEC_PUBLIC_IPS` | none | Addresses scans leave from. Shown on the Whitelist page |
| `WSEC_EGRESS_IP` | none | Bind outgoing connections to this local address |
| `WSEC_CONTACT` | none | Abuse contact shown on the Whitelist page |
| `WSEC_TRUST_PROXY` | `0` | Read the client address from `X-Forwarded-For` |
| `WSEC_SCANS_PER_HOUR` | `12` | Scans per visitor per hour |
| `WSEC_SCANS_PER_HOST_PER_HOUR` | `6` | Scans per target host per hour |
| `WSEC_MAX_CONCURRENT` | `4` | Scans running at once. More wait in a queue |
| `WSEC_RETENTION_DAYS` | `30` | Reports are deleted after this many days |
| `WSEC_DATA_DIR` | `./data` | Where `wsec.db` is kept |
| `WSEC_ALLOW_PRIVATE` | off | Development only. Allows private addresses and custom ports |

### Publishing real scanner IPs

The whitelist feature is only useful if the addresses are true. Run Wsec on a host with a fixed public address (or a small set), put those in `WSEC_PUBLIC_IPS`, and make sure outgoing scan traffic really leaves from them. If the machine has several addresses, set `WSEC_EGRESS_IP` so connections are bound to the published one. Check it from outside: scan a server you control and read the source address in its access log.

If the host sits behind NAT or a cloud gateway, publish the gateway's public address, not the machine's private one.

### Behind a reverse proxy

Put nginx or Caddy in front for HTTPS and set `WSEC_TRUST_PROXY=1` so rate limits use the visitor's address. Only do this when the proxy is the only thing that can reach the app, because the header is otherwise easy to fake. Set `WSEC_BASE_URL` to the public https address and the app will send HSTS.

## How it works

```
server/
  index.js          starts the server, purges old reports
  app.js            routing, static files, API, security headers
  scans.js          scan queue and concurrency limit
  verify.js         ownership proof for deep scans
  db.js             SQLite storage (node:sqlite)
  ratelimit.js      sliding window limiter
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

A tool that makes requests to addresses chosen by strangers can be turned against its own host. Wsec handles that in several places:

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
| `GET /api/scanner` | Published addresses, user agent, contact |
| `GET /api/checks` | The list of checks with explanations |
| `GET /api/health` | Liveness |

## Limits

- It checks the home page. Headers set only on other paths are not seen.
- It reads policies as written; it does not run the page, so it cannot tell whether a CSP breaks the site.
- DKIM cannot be checked from outside.
- The scan queue and rate limiter are in memory, so this is built for one process. Reports survive restarts, in-flight scans do not.
- Old TLS probing depends on the local OpenSSL build. When it cannot tell, the check says so instead of passing silently.

## Adding a check

Add an object to `CHECKS` in `server/scanner/checks.js` with an `id`, `category`, `title`, `severity`, `why`, `ref` and a `run(ctx)` function that returns `pass`, `fail`, `warn`, `info` or `skip`. If it needs data the scan does not collect yet, collect it in `server/scanner/scan.js`. Add a test in `test/checks.test.js`.
