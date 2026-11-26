# Fix notes — FlawRadar (merged)

## Merged from GitHub + local improvements

- **UI**: Kept the richer local UI (animated sky/clouds background, radar spinner, motion system, animated score count-up, dropzone file list, print styles, Watch nav item, legal disclaimers on home).
- **Features**: Local version is the base (Watch/alerts, source checks, backups, legal page placeholders, extra scanner checks such as old-software / exposed-keys / exposed-admin).
- **Security hardening** (from GitHub FIXES + local):
  - Removed the reserved TEST-NET example address from `FLAWRADAR_PUBLIC_IPS`; it is blank by default until the operator verifies real outbound addresses.
  - Validate configured public IP syntax and require `FLAWRADAR_EGRESS_IP` to be an IP actually assigned to a local network interface. A NAT gateway's public address belongs in `FLAWRADAR_PUBLIC_IPS`, not the local bind setting.
  - `FLAWRADAR_BLOCKED_HOSTS` opt-out enforcement for exact domains and all their subdomains (checked on every hop so redirects cannot bypass it).
  - Startup validation throws clear errors for bad IP configuration.
- LICENSE file restored/kept (Personal Evaluation License). Do not remove.
- Terms version remains the local one (`2026-11-22`).

## Configuration reminders

- Verify scanner egress addresses externally before publishing them in `FLAWRADAR_PUBLIC_IPS`.
- Use `FLAWRADAR_BLOCKED_HOSTS=example.com,example.org` for domains that must not be scanned.
- Never set `FLAWRADAR_ALLOW_PRIVATE=1` on a public instance.

## Verification

- Node.js requirement remains 22.13 or newer.
- Run `npm test` after changes.
