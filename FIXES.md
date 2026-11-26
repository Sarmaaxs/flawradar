# Fix notes — FlawRadar

## Changes
- Removed the reserved TEST-NET example address from `FLAWRADAR_PUBLIC_IPS`; it is blank by default until the operator verifies real outbound addresses.
- Validate configured public IP syntax and require `FLAWRADAR_EGRESS_IP` to be an IP actually assigned to a local network interface. A NAT gateway's public address belongs in `FLAWRADAR_PUBLIC_IPS`, not the local bind setting.
- Implemented `FLAWRADAR_BLOCKED_HOSTS` opt-out enforcement for exact domains and all their subdomains.
- Updated integration fixtures to include the current Terms version expected by the API.

## Configuration
- Verify scanner egress addresses externally before publishing them.
- Use `FLAWRADAR_BLOCKED_HOSTS=example.com,example.org` for domains that must not be scanned.

## Verification
- `npm test`: 86 passed, 0 failed.
- Node.js requirement remains 22.13 or newer.
