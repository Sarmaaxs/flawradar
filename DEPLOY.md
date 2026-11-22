# Going live

Run `npm run check` at any point. It lists what is still open. Anything marked FIX must be done before the site is public.

## 1. A server with fixed public addresses

The Whitelist page is the product's main promise, so the addresses on it must be true.

1. Put FlawRadar on a machine whose outgoing address does not change (a VPS is fine).
2. Set `FLAWRADAR_PUBLIC_IPS` to the address(es) scans leave from. If the machine has several addresses, also set `FLAWRADAR_EGRESS_IP` so scans use the published one.
3. Check it from outside: scan a server you control and read the source address in its access log. It must be the one you published.
4. Behind NAT or a cloud gateway, publish the gateway's public address, not the machine's private one.

## 2. HTTPS and the proxy

1. Put nginx or Caddy in front for HTTPS.
2. Set `FLAWRADAR_BASE_URL` to the public https address. Only then is HSTS sent.
3. Set `FLAWRADAR_TRUST_PROXY=1` only if the proxy is the sole way to reach the app (bind the app to 127.0.0.1, or firewall its port). Otherwise leave it at 0. If you forget it behind a proxy, every visitor shares one rate limit.

## 3. Legal details

Fill in every `FLAWRADAR_LEGAL_*` value and `FLAWRADAR_CONTACT`. They appear on the Terms, Acceptable Use and Privacy pages, and in the abuse contact on the Whitelist page. The pages are a draft that matches what the software does, not legal advice: have a lawyer in your jurisdiction read them, especially the governing law and dispute resolution parts.

When you change a page in a way that matters, change `termsVersion` in `server/config.js` so everyone accepts again.

## 4. Email for watches (optional)

Set `FLAWRADAR_SMTP_HOST`, `_PORT` (465 for TLS, 587 for STARTTLS), `_USER`, `_PASS` and `_FROM`. Use a sender address on a domain with SPF and DKIM set up at your mail provider, or the confirmation emails will land in spam. Without SMTP the Watch page says watches are off.

## 5. Backups and monitoring

1. Set `FLAWRADAR_BACKUP_DIR` (the Docker image uses `/data/backups` inside the volume). A copy is made at start and every `FLAWRADAR_BACKUP_INTERVAL_HOURS`; the newest `FLAWRADAR_BACKUP_KEEP` stay. `npm run backup` makes one on demand.
2. Copy the backup folder off the machine (rsync, rclone, your provider's snapshots). A backup on the same disk is not a backup.
3. Point an uptime monitor at `/api/health`. It returns 503 when the database does not answer. The body shows the time of the last backup and any backup error.
4. Restore: stop the app, replace `flawradar.db` in the data directory with a backup file, start the app.

## 6. Docker

```sh
docker build -t flawradar .
docker run -d --name flawradar -p 127.0.0.1:3000:3000 -v flawradar-data:/data --env-file .env flawradar
```

The image has a health check, runs as a non-root user and keeps the database and backups in the `/data` volume.

## 7. Tests on every push

`.github/workflows/test.yml` runs `npm test` and builds the image on every push and pull request.
