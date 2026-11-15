const HEADERS = {
  nginx: (host) =>
    `# Settings suggested by FlawRadar for ${host}\n` +
    '# Put these inside the server { } block that serves the site, then run: nginx -t && nginx -s reload\n' +
    '# Note: nginx drops server-level add_header lines inside any location that has its own add_header.',
  apache: (host) =>
    `# Settings suggested by FlawRadar for ${host}\n` +
    '# Needs mod_headers (a2enmod headers). Put these in the VirtualHost for the site, then reload Apache.',
  express: (host) => `// Settings suggested by FlawRadar for ${host}\n// Register this before your routes.`,
};

/**
 * One block of server configuration covering every failed or warned check that
 * has a header or protocol fix for the chosen server. Returns null if none.
 */
export function buildFixConfig(findings, server, host) {
  if (!HEADERS[server]) return null;
  const items = findings.filter(
    (f) => (f.status === 'fail' || f.status === 'warn') && f.fix?.bundle?.includes(server) && f.fix.snippets?.[server],
  );
  if (!items.length) return null;

  if (server === 'express') {
    const body = items.map((f) => `  // ${f.title}\n  ${f.fix.snippets.express}`).join('\n');
    return `${HEADERS.express(host)}\napp.use((req, res, next) => {\n${body}\n  next();\n});\n`;
  }
  const body = items.map((f) => `# ${f.title}\n${f.fix.snippets[server]}`).join('\n\n');
  return `${HEADERS[server](host)}\n\n${body}\n`;
}
