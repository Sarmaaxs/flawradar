// Small, forgiving extraction of the bits of HTML the checks care about.
// This is not a full parser; it only needs to find resources and forms.

const ATTR = /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;

function attrs(tag) {
  const out = {};
  const inner = tag.replace(/^<\s*[a-z0-9-]+/i, '').replace(/\/?>$/, '');
  ATTR.lastIndex = 0;
  let m;
  while ((m = ATTR.exec(inner))) {
    out[m[1].toLowerCase()] = m[2] ?? m[3] ?? m[4] ?? '';
  }
  return out;
}

function resolve(value, base) {
  if (!value) return null;
  try {
    return new URL(value.trim(), base).href;
  } catch {
    return null;
  }
}

export function extractResources(html, base) {
  const clean = html.replace(/<!--[\s\S]*?-->/g, '');
  const tags = (name) => clean.match(new RegExp(`<${name}\\b[^>]*>`, 'gi')) || [];

  const scripts = tags('script')
    .map(attrs)
    .filter((a) => a.src)
    .map((a) => ({ url: resolve(a.src, base), integrity: a.integrity || null }))
    .filter((x) => x.url);

  const styles = tags('link')
    .map(attrs)
    .filter((a) => /stylesheet/i.test(a.rel || '') && a.href)
    .map((a) => ({ url: resolve(a.href, base), integrity: a.integrity || null }))
    .filter((x) => x.url);

  const frames = [...tags('iframe'), ...tags('embed'), ...tags('object')]
    .map(attrs)
    .map((a) => ({ url: resolve(a.src || a.data, base) }))
    .filter((x) => x.url);

  const media = [...tags('img'), ...tags('audio'), ...tags('video'), ...tags('source')]
    .map(attrs)
    .map((a) => ({ url: resolve(a.src, base) }))
    .filter((x) => x.url);

  const forms = (clean.match(/<form\b[\s\S]*?<\/form>/gi) || []).map((block) => {
    const open = attrs(block.match(/^<form\b[^>]*>/i)[0]);
    return {
      action: open.action ? resolve(open.action, base) : base,
      hasPassword: /<input\b[^>]*\btype\s*=\s*["']?password/i.test(block),
    };
  });

  const generator = tags('meta')
    .map(attrs)
    .find((a) => (a.name || '').toLowerCase() === 'generator');

  return { scripts, styles, frames, media, forms, generator: generator?.content || null };
}
