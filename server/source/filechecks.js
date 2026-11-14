// Checks that need a whole file or the list of files, not one line.
import { FILE_CHECKS } from './rules.js';
import { baseName } from './paths.js';

const META = Object.fromEntries(FILE_CHECKS.map((c) => [c.id, c]));

function make(id, file, line, snippet) {
  const c = META[id];
  return {
    ruleId: id, title: c.title, severity: c.severity, confidence: c.confidence,
    file, line, snippet, why: c.why, fix: c.fix,
  };
}

const lineOf = (text, index) => text.slice(0, index).split('\n').length;

/**
 * @param files     readable files: [{ path, content }]
 * @param allPaths  every path in the upload, including ones that were skipped
 */
export function runFileChecks(files, allPaths) {
  const out = [];
  const lockfiles = allPaths.filter((p) => /(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(p));

  for (const { path, content } of files) {
    const name = baseName(path);
    const lower = name.toLowerCase();

    // .env with real values (but not .env.example and friends)
    if (/^\.env(?:\.[\w.-]+)?$/.test(lower) && !/\.(?:example|sample|template|dist)$/.test(lower)) {
      const m = /^[ \t]*(?:export[ \t]+)?[A-Z][A-Z0-9_]*[ \t]*=[ \t]*["']?[^\s"'#]+/m.exec(content);
      if (m) {
        const key = m[0].split('=')[0].trim().replace(/^export\s+/, '');
        out.push(make('file-env-committed', path, lineOf(content, m.index), `${key}=[value hidden]`));
      }
    }

    if (/^dockerfile(?:\.[\w.-]+)?$/.test(lower) && /^\s*FROM\s/im.test(content)) {
      if (!/^\s*USER\s+(?!root\b)\S+/im.test(content)) {
        out.push(make('file-docker-root', path, 1, 'No USER instruction found'));
      }
    }

    if (name === 'package.json') {
      let pkg = null;
      try {
        pkg = JSON.parse(content);
      } catch {
        /* a broken package.json is not our finding */
      }
      if (pkg && typeof pkg === 'object') {
        const find = (text) => {
          const i = content.indexOf(text);
          return i < 0 ? 1 : lineOf(content, i);
        };
        for (const group of ['dependencies', 'devDependencies', 'optionalDependencies']) {
          for (const [dep, range] of Object.entries(pkg[group] || {})) {
            if (typeof range !== 'string') continue;
            const where = find(`"${dep}"`);
            if (/^\s*(?:\*|latest|x)?\s*$/.test(range) || range.trim() === '*' || range.trim() === 'latest') {
              out.push(make('file-npm-unpinned', path, where, `"${dep}": "${range}"`));
            } else if (/^(?:https?:|git\+|git:|github:|[\w-]+\/[\w.-]+(?:#.*)?$)/.test(range.trim())) {
              const pinned = /#[0-9a-f]{7,40}$/i.test(range.trim());
              if (!pinned || /^http:/.test(range.trim())) {
                out.push(make('file-npm-url-dependency', path, where, `"${dep}": "${range}"`));
              }
            }
          }
        }
        for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) {
          const script = pkg.scripts?.[hook];
          if (typeof script === 'string' && /\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/.test(script)) {
            out.push(make('file-npm-install-script', path, find(`"${hook}"`), `"${hook}": "${script.slice(0, 120)}"`));
          }
        }
        const hasDeps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies }).length > 0;
        const dir = path.includes('/') ? path.slice(0, path.lastIndexOf('/') + 1) : '';
        const locked = lockfiles.some((p) => p.startsWith(dir));
        if (hasDeps && !locked) out.push(make('file-no-lockfile', path, 1, 'No package-lock.json, yarn.lock or pnpm-lock.yaml next to this file'));
      }
    }

    if (/^requirements[\w.-]*\.txt$/.test(lower)) {
      const lines = content.split('\n');
      let unpinned = 0;
      let first = 0;
      lines.forEach((raw, i) => {
        const text = raw.trim();
        if (!text || text.startsWith('#')) return;
        if (/^(?:-i|--index-url|--extra-index-url)\s+http:\/\//i.test(text) || /^--trusted-host\b/i.test(text) || /^(?:-e\s+)?http:\/\//i.test(text)) {
          out.push(make('file-pip-insecure-index', path, i + 1, text.slice(0, 160)));
          return;
        }
        if (text.startsWith('-')) return;
        if (!/(?:==|===|@)/.test(text)) {
          unpinned += 1;
          if (!first) first = i + 1;
        }
      });
      if (unpinned) out.push(make('file-pip-unpinned', path, first, `${unpinned} package${unpinned === 1 ? '' : 's'} without an exact version`));
    }
  }
  return out;
}