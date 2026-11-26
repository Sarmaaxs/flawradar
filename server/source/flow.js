// A step beyond one-line rules: follow request data through variables inside one file, and look
// for secrets by how random they look. Pure JavaScript with no Node imports, so it runs in the
// browser as well as on the server.
//
// What it does: finds a variable that was filled from request data (req.query, $_GET, request.args,
// location.hash ...), follows it into other variables, and reports when it reaches something
// dangerous (a SQL string, a shell command, eval, innerHTML, a file path, an outgoing request,
// a redirect). What it does not do: follow data across functions or files, understand
// frameworks, or know whether a custom function cleans a value. Findings are "medium" or "low"
// confidence for that reason.

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const PER_SINK_PER_FILE = 5;

// ---------------------------------------------------------------- JavaScript and TypeScript
const JS_SOURCE = /\b(?:req|request|ctx\.request|ctx|event)\.(?:query|body|params|headers|cookies|url|formData|json)\b|\b(?:window\.|document\.)?location\.(?:search|hash)\b|\bURLSearchParams\b|\bFormData\b|\bprocess\.argv\b|\b(?:req|request)\.(?:get|param)\s*\(/;
const JS_CLEAN = /\b(?:parseInt|parseFloat|Number|Boolean|encodeURIComponent|encodeURI|escape|escapeHtml|sanitize\w*|DOMPurify\.sanitize|validator\.\w+|isNaN)\s*\(|\bz\.\w+|\bJoi\b/;

const concatOf = (use) => (args) => {
  const u = use(args);
  if (!u) return false;
  // Inside a template literal, or joined to a string with +. A bare value passed as a parameter
  // (db.query(sql, [id])) is how it should be done, so that is not reported.
  return new RegExp('`[^`]*\\$\\{[^}]*' + esc(u) + '[^}]*\\}').test(args) ||
    new RegExp('[\'"]\\s*\\+\\s*[^,)]*' + esc(u)).test(args) ||
    new RegExp(esc(u) + '\\s*\\+\\s*[\'"`]').test(args);
};

const JS_SINKS = [
  { id: 'eval', title: 'Request data reaches eval()', severity: 'critical', confidence: 'medium', re: /\beval\s*\(|\bnew\s+Function\s*\(/,
    why: 'A value that came from the request is run as code. Anyone who controls the request can run their own code on the server or in the visitor\'s browser.',
    fix: 'Do not run strings as code. Parse the value as data (JSON.parse for JSON) or look it up in a fixed table of allowed actions.' },
  { id: 'shell', title: 'Request data reaches a shell command', severity: 'critical', confidence: 'medium', re: /\b(?:exec|execSync)\s*\(/,
    why: 'The value goes into a command line that a shell reads. Characters like ; | & and backticks let a visitor add their own commands.',
    fix: 'Use execFile or spawn with an argument array and no shell, and check the value against an allow-list first.' },
  { id: 'sql', title: 'Request data is joined into a SQL string', severity: 'high', confidence: 'medium', re: /\.(?:query|execute|raw|all|get|run|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(/, concat: true,
    why: 'The value becomes part of the SQL text, so a visitor can change what the query does (SQL injection): read other rows, bypass a login, change data.',
    fix: 'Use placeholders: db.query("SELECT * FROM users WHERE id = ?", [id]). Never build SQL by joining strings.' },
  { id: 'html', title: 'Request data is written into the page as HTML', severity: 'high', confidence: 'medium', re: /\.(?:innerHTML|outerHTML)\s*(?:\+)?=(?!=)|\.insertAdjacentHTML\s*\(|\bdocument\.write(?:ln)?\s*\(|dangerouslySetInnerHTML/,
    why: 'HTML built from request data runs as part of the page. A visitor who can influence it can run script in other people\'s browsers (cross-site scripting).',
    fix: 'Use textContent, or build elements with createElement. If you must insert HTML, clean it with a maintained sanitiser such as DOMPurify.' },
  { id: 'reflect', title: 'Request data is sent back inside HTML', severity: 'medium', confidence: 'low', re: /\bres\.(?:send|write|end)\s*\(/, htmlOnly: true,
    why: 'The response is HTML (Express sends strings as HTML) and contains the request value unescaped, which allows reflected cross-site scripting.',
    fix: 'Escape the value for HTML, use a template engine that escapes by default, or send JSON with res.json().' },
  { id: 'redirect', title: 'Request data decides where a redirect goes', severity: 'medium', confidence: 'medium', re: /\bres\.redirect\s*\(|\bwindow\.location(?:\.href)?\s*=(?!=)|\blocation\.(?:assign|replace)\s*\(/,
    why: 'A visitor can craft a link on your site that sends people to another site (open redirect), which is used for phishing.',
    fix: 'Redirect only to paths on your own site, or check the value against a list of allowed destinations.' },
  { id: 'path', title: 'Request data is used in a file path', severity: 'high', confidence: 'medium', re: /\b(?:fs\.)?(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync|readdir|readdirSync)\s*\(|\bres\.(?:sendFile|download)\s*\(|\bpath\.(?:join|resolve)\s*\(/,
    why: 'With "../" in the value a visitor can read or overwrite files outside the folder you meant (path traversal).',
    fix: 'Take only the file name (path.basename), join it to a fixed folder, then check that the resolved path still starts with that folder.' },
  { id: 'ssrf', title: 'Request data decides which address the server fetches', severity: 'high', confidence: 'medium', re: /\b(?:fetch|axios(?:\.(?:get|post|request))?|got|request|http\.get|https\.get|needle|superagent\.get)\s*\(/,
    why: 'A visitor can make your server request any address, including internal services and cloud metadata endpoints (server-side request forgery).',
    fix: 'Only fetch addresses from an allow-list of hosts, and refuse private and link-local IP ranges after DNS resolution.' },
  { id: 'require', title: 'Request data decides which module is loaded', severity: 'high', confidence: 'medium', re: /\brequire\s*\(|\bimport\s*\(/,
    why: 'A visitor who picks the module name can load code you did not intend.',
    fix: 'Map allowed names to modules in a fixed object and look the request value up in it.' },
];


// ---------------------------------------------------------------- Go
const GO_SOURCE = /\b(?:r\.URL\.Query\(\)|r\.FormValue\s*\(|r\.PostForm\.Get\s*\(|r\.Body\b|os\.Args\b|url\.Query\(\))/;
const GO_CLEAN = /\b(?:url\.QueryEscape|html\.EscapeString|template\.HTMLEscapeString|strconv\.Atoi|validator\.\w+)\s*\(/;
const GO_SINKS = [
  { id: 'sql', title: 'Request data is concatenated into a Go SQL query', severity: 'high', confidence: 'medium', re: /\b(?:Query|QueryRow|Exec|Prepare)\s*\(/, concat: true, why: 'Untrusted request data appears in SQL text. Use database placeholders instead of building query strings.', fix: 'Use db.QueryContext(ctx, "SELECT ... WHERE id = ?", id) with placeholders supported by your driver.' },
  { id: 'shell', title: 'Request data reaches a Go command invocation', severity: 'critical', confidence: 'medium', re: /\bexec\.Command(?:Context)?\s*\(/, concat: true, why: 'Request-controlled data may influence an operating-system command.', fix: 'Use a fixed executable and separate validated arguments. Never pass untrusted text through a shell.' },
  { id: 'path', title: 'Request data influences a Go file path', severity: 'high', confidence: 'medium', re: /\b(?:os\.Open|os\.ReadFile|os\.WriteFile|filepath\.Join)\s*\(/, concat: true, why: 'Untrusted input may select a file outside the intended directory.', fix: 'Resolve against a fixed root and verify the final path remains inside that root.' },
  { id: 'html', title: 'Request data is marked as trusted HTML in Go', severity: 'high', confidence: 'medium', re: /\btemplate\.HTML\s*\(/, why: 'Marking untrusted content as template.HTML bypasses automatic HTML escaping.', fix: 'Keep untrusted values as strings and let html/template escape them.' },
];

// ---------------------------------------------------------------- C and C++
const C_SOURCE = /\b(?:getenv|gets|fgets|scanf|fscanf|sscanf|recv|read)\s*\(|\b(?:argv|QUERY_STRING|HTTP_COOKIE|HTTP_USER_AGENT)\b/;
const C_CLEAN = /\b(?:strtol|strtoul|snprintf|html_escape|validate_[A-Za-z0-9_]*)\s*\(/;
const C_SINKS = [
  { id: 'shell', title: 'Untrusted input may reach a C command function', severity: 'critical', confidence: 'medium', re: /\b(?:system|popen|execlp|execvp)\s*\(/, why: 'Input from an external source appears in a process-launch call.', fix: 'Avoid shell command construction. Use a fixed executable and carefully separated, validated arguments.' },
  { id: 'format', title: 'Untrusted input may be used as a C format string', severity: 'high', confidence: 'medium', re: /\b(?:printf|fprintf|sprintf|snprintf|syslog)\s*\(/, why: 'A user-controlled format string can cause memory-safety problems or disclose data.', fix: 'Use a constant format string, for example printf("%s", value), and validate the input.' },
  { id: 'memory', title: 'Untrusted input may reach a C memory-copy function', severity: 'high', confidence: 'medium', re: /\b(?:strcpy|strcat|strncpy|memcpy|gets)\s*\(/, why: 'External data reaches a low-level copy operation. Check destination capacity and input length.', fix: 'Prefer bounded APIs with explicit sizes, validate lengths, and use memory-safe abstractions where possible.' },
];

// ---------------------------------------------------------------- Python
const PY_SOURCE = /\b(?:request|req)\.(?:args|form|values|json|get_json|GET|POST|data|cookies|headers|files|view_args|query_params|path_params)\b/;
const PY_CLEAN = /\b(?:int|float|bool|escape|quote|secure_filename|markupsafe\.escape)\s*\(/;
const PY_SINKS = [
  { id: 'sql', title: 'Request data is joined into a SQL string', severity: 'high', confidence: 'medium', re: /\.(?:execute|executemany|raw)\s*\(/, concat: 'py',
    why: 'The value becomes part of the SQL text, so a visitor can change what the query does (SQL injection).',
    fix: 'Pass values separately: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,)).' },
  { id: 'shell', title: 'Request data reaches a shell command', severity: 'critical', confidence: 'medium', re: /\bos\.(?:system|popen)\s*\(|\bsubprocess\.\w+\([^\n]*shell\s*=\s*True|\bsubprocess\.(?:getoutput|getstatusoutput)\s*\(/,
    why: 'The value goes into a command line that a shell reads, so a visitor can add their own commands.',
    fix: 'Use subprocess.run([...], shell=False) with a list of arguments and validate the value first.' },
  { id: 'eval', title: 'Request data reaches eval() or exec()', severity: 'critical', confidence: 'medium', re: /\b(?:eval|exec)\s*\(|\brender_template_string\s*\(/,
    why: 'A value from the request is run as code or as a template, which lets a visitor run their own code on the server.',
    fix: 'Do not run request data as code. Use ast.literal_eval or json.loads for data, and fixed template files for pages.' },
  { id: 'path', title: 'Request data is used in a file path', severity: 'high', confidence: 'medium', re: /\bopen\s*\(|\bsend_file\s*\(|\bsend_from_directory\s*\(|\bos\.path\.join\s*\(/,
    why: 'With "../" in the value a visitor can read files outside the folder you meant (path traversal).',
    fix: 'Use werkzeug.utils.secure_filename, join to a fixed folder, and check the resolved path stays inside it.' },
  { id: 'ssrf', title: 'Request data decides which address the server fetches', severity: 'high', confidence: 'medium', re: /\brequests\.(?:get|post|put|head|request)\s*\(|\burllib\.request\.urlopen\s*\(|\bhttpx\.(?:get|post)\s*\(/,
    why: 'A visitor can make your server request any address, including internal services (server-side request forgery).',
    fix: 'Fetch only allow-listed hosts and refuse private IP ranges after resolving the name.' },
  { id: 'redirect', title: 'Request data decides where a redirect goes', severity: 'medium', confidence: 'medium', re: /\bredirect\s*\(/,
    why: 'A visitor can craft a link on your site that sends people to another site (open redirect).',
    fix: 'Redirect only to paths on your own site, or check against a list of allowed destinations.' },
  { id: 'deserialize', title: 'Request data is deserialised unsafely', severity: 'critical', confidence: 'medium', re: /\bpickle\.loads?\s*\(|\byaml\.load\s*\((?![^\n]*Loader\s*=\s*(?:yaml\.)?SafeLoader)/,
    why: 'Unpickling or loading unsafe YAML from request data lets a visitor run code on the server.',
    fix: 'Use json.loads, or yaml.safe_load.' },
];

// ---------------------------------------------------------------- PHP
const PHP_SOURCE = /\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|\$_SERVER\s*\[\s*['"](?:QUERY_STRING|REQUEST_URI|HTTP_[A-Z_]+|PATH_INFO)['"]\s*\]/;
const PHP_CLEAN = /\b(?:intval|floatval|abs|htmlspecialchars|htmlentities|mysqli_real_escape_string|real_escape_string|addslashes|filter_var|basename|esc_html|esc_attr|esc_url|sanitize_\w+)\s*\(|\(\s*(?:int|float|bool)\s*\)/;
const PHP_SINKS = [
  { id: 'sql', title: 'Request data is joined into a SQL string', severity: 'high', confidence: 'medium', re: /\b(?:mysqli_query|mysql_query|pg_query|sqlsrv_query)\s*\(|->(?:query|exec|prepare|real_query)\s*\(/, concat: 'php',
    why: 'The value becomes part of the SQL text, so a visitor can change what the query does (SQL injection).',
    fix: 'Use prepared statements with bound parameters: $stmt = $pdo->prepare("... WHERE id = ?"); $stmt->execute([$id]);' },
  { id: 'shell', title: 'Request data reaches a shell command', severity: 'critical', confidence: 'medium', re: /\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(|`[^`]*\$/,
    why: 'The value goes into a command line, so a visitor can add their own commands.',
    fix: 'Avoid shell commands. If you must, use escapeshellarg() on every value and an allow-list for the command.' },
  { id: 'eval', title: 'Request data reaches eval()', severity: 'critical', confidence: 'medium', re: /\beval\s*\(|\bassert\s*\(|\bcreate_function\s*\(|\bunserialize\s*\(/,
    why: 'A value from the request is run as code or unserialised, which lets a visitor run their own code or objects on the server.',
    fix: 'Do not run request data as code. Use json_decode for data.' },
  { id: 'include', title: 'Request data decides which file is included', severity: 'critical', confidence: 'medium', re: /\b(?:include|include_once|require|require_once)\b/,
    why: 'A visitor who picks the file can include local files, or remote code when allow_url_include is on (file inclusion).',
    fix: 'Map allowed names to fixed file names and include only those.' },
  { id: 'xss', title: 'Request data is printed into the page', severity: 'high', confidence: 'medium', re: /\b(?:echo|print)\b|<\?=/,
    why: 'The value is written into the HTML without escaping, which allows cross-site scripting.',
    fix: 'Escape on output: echo htmlspecialchars($value, ENT_QUOTES, "UTF-8");' },
  { id: 'path', title: 'Request data is used in a file path', severity: 'high', confidence: 'medium', re: /\b(?:file_get_contents|fopen|readfile|file_put_contents|unlink|move_uploaded_file|copy|rename)\s*\(/,
    why: 'With "../" in the value a visitor can read or overwrite files outside the folder you meant (path traversal).',
    fix: 'Take only basename(), join it to a fixed folder, and check realpath() stays inside that folder.' },
  { id: 'redirect', title: 'Request data decides where a redirect goes', severity: 'medium', confidence: 'medium', re: /\bheader\s*\(\s*['"]Location:/i,
    why: 'A visitor can craft a link on your site that sends people to another site (open redirect).',
    fix: 'Redirect only to paths on your own site, or check against a list of allowed destinations.' },
];

const LANGS = {
  js: { exts: ['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'vue', 'svelte'], source: JS_SOURCE, clean: JS_CLEAN, sinks: JS_SINKS, before: '(?<![\\w$.])', after: '(?![\\w$])', prefix: '' },
  py: { exts: ['py'], source: PY_SOURCE, clean: PY_CLEAN, sinks: PY_SINKS, before: '(?<![\\w.])', after: '(?!\\w)', prefix: '' },
  php: { exts: ['php', 'phtml', 'inc'], source: PHP_SOURCE, clean: PHP_CLEAN, sinks: PHP_SINKS, before: '(?<![\\w])', after: '(?!\\w)', prefix: '\\$' },
  go: { exts: ['go'], source: GO_SOURCE, clean: GO_CLEAN, sinks: GO_SINKS, before: '(?<![\\w.])', after: '(?![\\w])', prefix: '' },
  c: { exts: ['c', 'h', 'cc', 'cpp', 'hpp'], source: C_SOURCE, clean: C_CLEAN, sinks: C_SINKS, before: '(?<![\\w])', after: '(?![\\w])', prefix: '' },
};
const LANG_BY_EXT = Object.fromEntries(Object.entries(LANGS).flatMap(([k, v]) => v.exts.map((e) => [e, k])));

function assignment(lang, line) {
  if (lang === 'php') {
    const m = /^\s*\$([A-Za-z_]\w*)\s*(?:\.)?=(?!=)\s*(.+?);?\s*$/.exec(line);
    return m ? { name: m[1], rhs: m[2] } : null;
  }
  if (lang === 'py') {
    const m = /^\s*([A-Za-z_]\w*)\s*(?:\+)?=(?!=)\s*(.+)$/.exec(line);
    return m ? { name: m[1], rhs: m[2] } : null;
  }
  if (lang === 'go') {
    const m = /^\s*(?:var\s+)?([A-Za-z_]\w*)\s*(?::=|=(?!=))\s*(.+)$/.exec(line);
    return m ? { name: m[1], rhs: m[2] } : null;
  }
  if (lang === 'c') {
    const m = /^\s*(?:(?:const|volatile|static|unsigned|signed|char|int|long|short|size_t|wchar_t|void|\w+_t)\s+|[A-Za-z_]\w*\s*\*+\s*)(?:\*\s*)?([A-Za-z_]\w*)\s*=(?!=)\s*(.+);?\s*$/.exec(line);
    return m ? { name: m[1], rhs: m[2] } : null;
  }
  const m = /^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*(?:\+)?=(?![=>])\s*(.+)$/.exec(line);
  return m ? { name: m[1], rhs: m[2] } : null;
}

function destructured(line, source) {
  const m = /^\s*(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(.+)$/.exec(line);
  if (!m || !source.test(m[2])) return [];
  return m[1].split(',').map((part) => {
    const alias = part.split(':').pop().split('=')[0].trim();
    return /^[A-Za-z_$][\w$]*$/.test(alias) ? alias : null;
  }).filter(Boolean);
}

function isCommentLine(trimmed, lang) {
  if (lang === 'py') return trimmed.startsWith('#');
  return trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*') || (lang === 'php' && trimmed.startsWith('#'));
}

/**
 * Follow request data through one file.
 * @param path     file path (for the report)
 * @param ext      lower-case extension
 * @param rows     the file split into lines
 * @param flagged  line numbers that already have a finding from the line rules
 */
export function flowFindings(path, ext, rows, flagged = new Set()) {
  const lang = LANGS[LANG_BY_EXT[ext]];
  if (!lang) return [];
  const langName = LANG_BY_EXT[ext];
  const tainted = new Map(); // name -> line where it got its value
  const counts = new Map();
  const out = [];
  let nameRe = null;
  const rebuild = () => {
    nameRe = tainted.size
      ? new RegExp(`${lang.before}${lang.prefix}(${[...tainted.keys()].map(esc).join('|')})${lang.after}`)
      : null;
  };

  for (let n = 0; n < rows.length; n += 1) {
    const line = rows[n];
    if (line.length > 1000 || line.length < 6) continue;
    const trimmed = line.trim();
    if (isCommentLine(trimmed, langName)) continue;

    // 1. Does this line use tainted data in a dangerous place?
    for (const sink of lang.sinks) {
      const m = sink.re.exec(line);
      if (!m) continue;
      if (sink.only && !sink.only.test(line)) continue;
      const args = line.slice(m.index + m[0].length);
      const direct = lang.source.exec(args);
      const named = nameRe ? nameRe.exec(args) : null;
      if (!direct && !named) continue;
      const usedName = named ? named[1] : null;
      const usedText = named ? `${lang.prefix ? '$' : ''}${usedName}` : direct[0];

      if (sink.concat) {
        const useRe = esc(usedText);
        const ok = langName === 'js'
          ? concatOf(() => usedText)(args)
          : langName === 'py'
            ? new RegExp(`f['"][^'"]*\\{[^}]*${useRe}|['"]\\s*(?:\\+|%)\\s*[^,)]*${useRe}|${useRe}\\s*\\+\\s*['"]|\\.format\\([^)]*${useRe}`).test(line)
            : new RegExp(`["'][^"']*${useRe}|["']\\s*\\.\\s*${useRe}|${useRe}\\s*\\.\\s*["']`).test(args);
        if (!ok) continue;
      }
      if (sink.htmlOnly && !/</.test(line)) continue;
      if (flagged.has(n + 1)) continue;
      if (lang.clean.test(args.slice(0, args.indexOf(usedText) + usedText.length))) continue; // wrapped in a cleaner on the spot

      const count = counts.get(sink.id) || 0;
      if (count >= PER_SINK_PER_FILE) continue;
      counts.set(sink.id, count + 1);
      const origin = named ? tainted.get(usedName) : n + 1;
      const confidenceScore = named ? 0.84 : 0.96;
      out.push({
        ruleId: `flow-${sink.id}`, title: sink.title, severity: sink.severity, confidence: confidenceScore >= 0.9 ? 'high' : 'medium', detection: { method: 'context-weighted-taint-correlation', score: confidenceScore, sourceLine: origin, sinkLine: n + 1, aliasHops: named ? 1 : 0 },
        file: path, line: n + 1, snippet: trimmed.length > 200 ? `${trimmed.slice(0, 200)}...` : trimmed,
        why: `${sink.why} ${named ? `The value "${usedName}" is filled from request data on line ${origin}.` : 'The request data is used right here.'} Found by following the value inside this file; if a function in between checks or cleans it, this is a false alarm.`,
        fix: sink.fix,
      });
    }

    // 2. Does this line make a variable tainted?
    for (const name of destructured(line, lang.source)) tainted.set(name, n + 1);
    const a = assignment(langName, line);
    if (a) {
      const fromSource = lang.source.test(a.rhs);
      const tmp = nameRe ? nameRe.exec(a.rhs) : null;
      if ((fromSource || tmp) && !lang.clean.test(a.rhs)) {
        if (!tainted.has(a.name)) tainted.set(a.name, tmp ? tainted.get(tmp[1]) : n + 1);
      } else if (tainted.has(a.name) && !fromSource && !tmp) {
        tainted.delete(a.name); // overwritten with something harmless
      }
    }
    if (tainted.size && (a || destructured(line, lang.source).length)) rebuild();
  }
  return out;
}

// ---------------------------------------------------------------- secrets by randomness
const SECRET_NAME = /(?:api[_-]?key|secret|token|passw(?:or)?d|passwd|pwd|auth|credential|private[_-]?key|access[_-]?key|client[_-]?secret|signing[_-]?key)\w*/i;
const ASSIGN_STRING = /([A-Za-z_][\w.-]*)["']?\s*(?::|=|=>)\s*["']([^"'\s]{16,200})["']/g;
const PLACEHOLDER = /(?:example|sample|placeholder|changeme|change[_-]?me|your[_-]|<|>|xxxx|\*{4}|dummy|todo|test|fake|process\.env|\$\{|%\(|\{\{|^[a-z]+(?:[-_ ][a-z]+)+$)/i;

export function entropy(s) {
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const c of freq.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Names that look like secrets, holding values that look random. Complements the fixed-format rules. */
export function secretFindings(path, rows, flagged = new Set()) {
  const out = [];
  for (let n = 0; n < rows.length && out.length < 5; n += 1) {
    const line = rows[n];
    if (line.length > 1000 || flagged.has(n + 1)) continue;
    const trimmed = line.trim();
    if (/^(?:\/\/|#|\*|\/\*)/.test(trimmed)) continue;
    ASSIGN_STRING.lastIndex = 0;
    let m;
    while ((m = ASSIGN_STRING.exec(line))) {
      const [, name, value] = m;
      if (!SECRET_NAME.test(name) || PLACEHOLDER.test(value) || /^https?:/i.test(value) || /^[\w./-]+\.(?:js|css|png|json|html|svg)$/i.test(value)) continue;
      if (!/[A-Za-z]/.test(value) || !/[0-9]/.test(value) && entropy(value) < 4.2) continue;
      if (entropy(value) < 3.6) continue;
      const masked = `${value.slice(0, 3)}***`;
      out.push({
        ruleId: 'secret-entropy', title: 'A random-looking value is stored in a secret-named variable', severity: 'high', confidence: 'low',
        file: path, line: n + 1, snippet: trimmed.split(value).join(masked).slice(0, 200),
        why: `"${name}" holds a long, random-looking string. That is what a real key, token or password looks like. Anyone who can read the code or its history can use it.`,
        fix: 'Move the value out of the code into an environment variable or a secrets manager, and rotate it, because it is now in your repository history.',
      });
      break;
    }
  }
  return out;
}

/** For the rule list on the source page. */
export function flowCatalog() {
  const row = (applies) => (r) => ({ id: `flow-${r.id}`, title: r.title.replace(/^Request data/, 'Request data (followed through variables)'), severity: r.severity, confidence: r.confidence, applies });
  return [
    ...JS_SINKS.map(row('JavaScript, followed in one file')),
    ...PY_SINKS.map(row('Python, followed in one file')),
    ...PHP_SINKS.map(row('PHP, followed in one file')),
    ...GO_SINKS.map(row('Go, followed in one file')),
    ...C_SINKS.map(row('C and C++, followed in one file')),
    { id: 'secret-entropy', title: 'Random-looking value in a secret-named variable', severity: 'high', confidence: 'low', applies: 'any' },
  ];
}

