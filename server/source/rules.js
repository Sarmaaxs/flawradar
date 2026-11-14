// Static rules for source code. Each rule looks at one line at a time.
//
// This is pattern matching, not data-flow analysis. It finds the obvious,
// common mistakes. It does not know whether a value is user-controlled, so
// every rule carries a confidence (high, medium, low) that says how often a
// match is a real problem rather than a lookalike.

const JS = ['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'vue', 'svelte'];
const PY = ['py'];
const PHP = ['php', 'phtml', 'inc'];
const MARKUP = ['html', 'htm', 'ejs', 'hbs', 'twig', 'php', 'phtml', 'vue', 'svelte'];

const SQL = '(?:SELECT\\b[^"\'`]*?\\bFROM|INSERT\\s+INTO|UPDATE\\s+\\w+\\s+SET|DELETE\\s+FROM)';
const PLACEHOLDER = /^(?:your|my|example|sample|change|replace|insert|enter|dummy|fake|test|todo|x{3,}|\*+|<|\$\{|\{\{|%|\.\.\.)/i;
const FROM_ENV = /process\.env|os\.environ|getenv|ENV\[|config\(|settings\./i;
const INPUT_WORDS = /token|secret|password|passwd|session|\bkey\b|otp|nonce|salt|csrf/i;

export const RULES = [
  // ------------------------------------------------------------------ Secrets
  {
    id: 'secret-aws-key', title: 'AWS access key ID in source', severity: 'critical', confidence: 'high',
    secret: true, pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
    why: 'Anyone who can read this file can use the key. Keys pushed to a repository are found by bots within minutes.',
    fix: 'Revoke the key in the AWS console now, create a new one, and load it from the environment or a secrets manager. Removing it from the file is not enough if it was ever committed.',
  },
  {
    id: 'secret-private-key', title: 'Private key in source', severity: 'critical', confidence: 'high',
    secret: true, pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/,
    why: 'A private key in a deployable folder can be downloaded or copied, and then used to impersonate the server or sign in as you.',
    fix: 'Replace the key. Keep keys outside the project and outside the web root, and load them from the server at run time.',
  },
  {
    id: 'secret-github-token', title: 'GitHub token in source', severity: 'critical', confidence: 'high',
    secret: true, pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
    why: 'The token gives access to your repositories with whatever rights it was issued with.',
    fix: 'Revoke it at github.com/settings/tokens and issue a new one with the smallest scope that works. Store it as a secret, not in a file.',
  },
  {
    id: 'secret-slack-token', title: 'Slack token in source', severity: 'high', confidence: 'high',
    secret: true, pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
    why: 'The token lets others read and post in your Slack workspace.',
    fix: 'Revoke it in the Slack app settings, create a new one, and keep it in the environment.',
  },
  {
    id: 'secret-stripe-live', title: 'Stripe live secret key in source', severity: 'critical', confidence: 'high',
    secret: true, pattern: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/,
    why: 'A live Stripe secret key can create charges and refunds and read customer data.',
    fix: 'Roll the key in the Stripe dashboard and load the new one from the environment. Only the publishable key (pk_live_) belongs in front-end code.',
  },
  {
    id: 'secret-google-api-key', title: 'Google API key in source', severity: 'medium', confidence: 'medium',
    secret: true, pattern: /\bAIza[0-9A-Za-z_-]{35}\b/,
    why: 'Google API keys in front-end code are common and can be fine if restricted, but an unrestricted key can be used by anyone and billed to you.',
    fix: 'In the Google Cloud console, restrict the key to your domains or app and to the APIs it needs. Keep server-side keys out of client code.',
  },
  {
    id: 'secret-db-url', title: 'Database password in a connection string', severity: 'high', confidence: 'medium',
    secret: true, redactCapture: true, skipTests: true,
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/"']+:([^\s@/"']{3,})@/i,
    filter: (line, m) => !/^(?:password|pass|secret|changeme|\$|\{|<|%|\*)/i.test(m[1]),
    why: 'A password in a connection string ends up in version control, logs and error messages.',
    fix: 'Read the connection string from an environment variable and rotate the password.',
  },
  {
    id: 'secret-jwt-literal', title: 'JWT signed with a hard-coded secret', severity: 'high', confidence: 'medium',
    exts: JS, secret: true, redactCapture: true, skipTests: true,
    pattern: /\bjwt\.sign\s*\([^)]*,\s*["'`]([^"'`]{4,})["'`]/,
    why: 'Anyone who sees the source can sign their own tokens and log in as any user.',
    fix: 'Use a long random secret from the environment, and rotate it. Existing tokens signed with the old one stop being valid.',
  },
  {
    id: 'secret-hardcoded', title: 'Hard-coded password, key or token', severity: 'high', confidence: 'medium',
    secret: true, redactCapture: true, skipTests: true,
    pattern: /(?:password|passwd|pwd|secret[_-]?key|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key)\b["']?\s*[:=]\s*["']([^"'\s]{8,})["']/i,
    filter: (line, m) =>
      !PLACEHOLDER.test(m[1]) && !FROM_ENV.test(line) && !/^(.)\1+$/.test(m[1]) && new Set(m[1]).size > 3,
    why: 'Credentials in source are copied with the code: into repositories, backups, zip files and screenshots.',
    fix: 'Move the value to an environment variable or a secrets manager, rotate it, and read it at run time. Commit an .env.example with empty values.',
  },

  // --------------------------------------------------------------- JavaScript
  {
    id: 'js-eval', title: 'eval() runs a string as code', severity: 'high', confidence: 'medium', exts: JS,
    pattern: /(?<![.\w$])eval\s*\(/,
    why: 'If any part of the string comes from a user, an attacker can run their own code.',
    fix: 'Parse data with JSON.parse. Replace dynamic code with a lookup table or a function reference.',
  },
  {
    id: 'js-new-function', title: 'new Function() builds code from a string', severity: 'high', confidence: 'medium', exts: JS,
    pattern: /\bnew\s+Function\s*\(/,
    why: 'It is eval() by another name: user input in the string means code execution.',
    fix: 'Use a plain function. If you need user-defined logic, use a restricted expression parser.',
  },
  {
    id: 'js-innerhtml', title: 'innerHTML or outerHTML assigned a dynamic value', severity: 'medium', confidence: 'medium', exts: JS,
    pattern: /\.(?:innerHTML|outerHTML)\s*\+?=(?!=)/,
    filter: (line) => {
      const rhs = line.slice(line.search(/\.(?:innerHTML|outerHTML)/)).replace(/^[^=]*=/, '').trim();
      return rhs !== '' && !/^["'`][^"'`$+]*["'`];?$/.test(rhs);
    },
    why: 'Markup built from user-supplied text lets an attacker add script (cross-site scripting).',
    fix: 'Use textContent for text, or build elements with createElement. If you must insert HTML, sanitise it first with a library such as DOMPurify.',
  },
  {
    id: 'js-document-write', title: 'document.write() with dynamic content', severity: 'medium', confidence: 'medium', exts: JS,
    pattern: /\bdocument\.write(?:ln)?\s*\(/,
    why: 'document.write inserts raw markup. With user-supplied data it is cross-site scripting.',
    fix: 'Create and append DOM nodes instead.',
  },
  {
    id: 'js-react-dangerous-html', title: 'dangerouslySetInnerHTML', severity: 'medium', confidence: 'medium', exts: JS,
    pattern: /\bdangerouslySetInnerHTML\b/,
    why: 'React normally escapes everything. This switches that off for the value you give it.',
    fix: 'Render the content as React elements. If it is HTML you do not control, sanitise it first.',
  },
  {
    id: 'js-vue-vhtml', title: 'v-html renders raw HTML', severity: 'medium', confidence: 'medium', exts: ['vue', 'html', 'htm'],
    pattern: /\bv-html\s*=/,
    why: 'Vue does not escape v-html content, so untrusted text becomes cross-site scripting.',
    fix: 'Use {{ }} interpolation. If you need HTML, sanitise it first.',
  },
  {
    id: 'js-command-injection', title: 'Shell command built from a string', severity: 'high', confidence: 'medium', exts: JS,
    pattern: /\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+)/,
    why: 'A shell command with user input in it lets an attacker add their own commands (for example ; rm -rf).',
    fix: 'Use execFile or spawn with an argument array and no shell, so input is never parsed as a command.',
  },
  {
    id: 'js-spawn-shell', title: 'child process started with shell: true', severity: 'medium', confidence: 'medium', exts: JS,
    pattern: /\bshell\s*:\s*true\b/,
    why: 'With a shell, any special character in an argument is interpreted. That is the usual way command injection happens.',
    fix: 'Remove shell: true and pass arguments as an array.',
  },
  {
    id: 'js-sql-template', title: 'SQL built with template-literal interpolation', severity: 'high', confidence: 'medium', exts: JS,
    pattern: new RegExp('`\\s*' + SQL + '[^`]*\\$\\{', 'i'),
    why: 'A value placed inside the SQL text can change the query (SQL injection). Template literals do not escape anything.',
    fix: 'Use placeholders and pass the values separately: db.query("SELECT * FROM users WHERE id = $1", [id]). ORMs and query builders do this for you.',
  },
  {
    id: 'js-sql-concat', title: 'SQL built by string concatenation', severity: 'high', confidence: 'medium', exts: [...JS, ...PY],
    pattern: new RegExp('(?:"\\s*' + SQL + '[^"]*"|\'\\s*' + SQL + '[^\']*\')\\s*\\+\\s*[$\\w(]', 'i'),
    why: 'A value joined into the SQL text can change the query (SQL injection).',
    fix: 'Use parameterised queries with placeholders and pass the values separately.',
  },
  {
    id: 'js-path-traversal', title: 'File path taken from the request', severity: 'high', confidence: 'medium', exts: JS,
    pattern: /\b(?:readFile|readFileSync|createReadStream|sendFile|unlink|unlinkSync|writeFile|writeFileSync)\s*\([^)]*\breq\.(?:params|query|body)\b/,
    why: 'A request value like ../../etc/passwd can reach files outside the folder you meant to serve.',
    fix: 'Resolve the path, then check it starts with your base directory. Better, look files up by an id you control instead of by a name from the request.',
  },
  {
    id: 'js-open-redirect', title: 'Redirect to an address from the request', severity: 'medium', confidence: 'medium', exts: JS,
    pattern: /\bres\.redirect\s*\([^)]*\breq\.(?:query|params|body)\b/,
    why: 'Attackers send victims a link on your domain that bounces them to a phishing page.',
    fix: 'Redirect only to relative paths or to a fixed list of allowed addresses.',
  },
  {
    id: 'js-tls-verification-off', title: 'TLS certificate checking turned off', severity: 'high', confidence: 'high', exts: JS,
    pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0/,
    why: 'The program will accept any certificate, so anyone on the network path can read and change its HTTPS traffic.',
    fix: 'Remove the setting. For a private CA, give Node the CA file with the ca option or NODE_EXTRA_CA_CERTS.',
  },
  {
    id: 'js-weak-hash', title: 'MD5 or SHA-1 used', severity: 'low', confidence: 'medium', exts: JS,
    pattern: /createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)/,
    why: 'Both are broken for security uses. They are fine for cache keys and checksums, not for passwords or signatures.',
    fix: 'For passwords use bcrypt, scrypt or argon2. For other hashing use SHA-256 or better.',
  },
  {
    id: 'js-predictable-random', title: 'Math.random() used for a secret value', severity: 'medium', confidence: 'medium', exts: JS,
    pattern: /Math\.random\s*\(\)/,
    filter: (line) => INPUT_WORDS.test(line),
    why: 'Math.random is predictable. Tokens, codes and ids made with it can be guessed.',
    fix: 'Use crypto.randomBytes or crypto.randomUUID.',
  },
  {
    id: 'js-cookie-flags-off', title: 'Cookie flag secure or httpOnly set to false', severity: 'medium', confidence: 'medium', exts: JS,
    pattern: /\b(?:httpOnly|secure)\s*:\s*false\b/,
    why: 'Without httpOnly a script can read the cookie. Without secure it also travels over plain HTTP.',
    fix: 'Set both to true (secure only works over HTTPS) and add sameSite: "lax".',
  },
  {
    id: 'js-jwt-none', title: 'JWT verification allows the "none" algorithm', severity: 'critical', confidence: 'high', exts: JS,
    pattern: /algorithms?\s*:\s*\[\s*["']none["']/i,
    why: 'Tokens with no signature are accepted, so anyone can create a valid login token.',
    fix: 'List only the real algorithm, for example algorithms: ["HS256"].',
  },
  {
    id: 'js-postmessage-star', title: 'postMessage sent to any origin', severity: 'low', confidence: 'medium', exts: JS,
    pattern: /postMessage\s*\([^)]*,\s*["']\*["']\s*\)/,
    why: 'Whatever page holds the target window receives the message, including a page an attacker opened.',
    fix: 'Give the exact target origin instead of "*".',
  },
  {
    id: 'js-token-in-localstorage', title: 'Token or password stored in localStorage', severity: 'low', confidence: 'medium', exts: JS,
    pattern: /localStorage\.setItem\s*\(\s*["'][^"']*(?:token|jwt|secret|password)[^"']*["']/i,
    why: 'Any script on the page can read localStorage, so one XSS bug exposes every session.',
    fix: 'Prefer an httpOnly cookie for session tokens.',
  },

  // ------------------------------------------------------------------- Python
  {
    id: 'py-eval-exec', title: 'eval() or exec() runs a string as code', severity: 'high', confidence: 'medium', exts: PY,
    pattern: /(?<![.\w])(?:eval|exec)\s*\(/,
    why: 'If any part of the string comes from a user, they can run their own code.',
    fix: 'Use ast.literal_eval for data, or a lookup table for choosing behaviour.',
  },
  {
    id: 'py-pickle', title: 'Unpickling data can run code', severity: 'high', confidence: 'medium', exts: PY,
    pattern: /\b(?:pickle|cPickle|dill)\.loads?\s*\(/,
    why: 'A crafted pickle file runs arbitrary code when loaded. It must never be used on data from outside.',
    fix: 'Use JSON or another data-only format. If you must unpickle, only do it for files you wrote and signed.',
  },
  {
    id: 'py-yaml-load', title: 'yaml.load without a safe loader', severity: 'high', confidence: 'medium', exts: PY,
    pattern: /\byaml\.load\s*\(/,
    filter: (line) => !/Loader\s*=\s*(?:yaml\.)?C?SafeLoader/.test(line),
    why: 'The default loader can build arbitrary Python objects, which can run code.',
    fix: 'Use yaml.safe_load.',
  },
  {
    id: 'py-shell-true', title: 'subprocess called with shell=True', severity: 'high', confidence: 'medium', exts: PY,
    pattern: /\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True/,
    why: 'With a shell, special characters in any argument are interpreted, which is how command injection happens.',
    fix: 'Pass a list of arguments and drop shell=True.',
  },
  {
    id: 'py-os-system', title: 'os.system or os.popen with a built string', severity: 'high', confidence: 'medium', exts: PY,
    pattern: /\bos\.(?:system|popen)\s*\(\s*(?:f["']|[^)]*(?:\+|%|\.format))/,
    why: 'A command built from a string can be changed by user input.',
    fix: 'Use subprocess.run with a list of arguments.',
  },
  {
    id: 'py-sql-format', title: 'SQL built with f-strings, % or format()', severity: 'high', confidence: 'medium', exts: PY,
    pattern: new RegExp(
      '\\.execute(?:many|script)?\\s*\\(\\s*(?:f["\']|["\'][^"\']*["\']\\s*(?:%|\\.format\\s*\\())|\\bf["\']\\s*' + SQL + '[^"\']*\\{',
      'i',
    ),
    why: 'Values formatted into the SQL text can change the query (SQL injection).',
    fix: 'Pass values as parameters: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,)).',
  },
  {
    id: 'py-debug-on', title: 'Debug mode enabled', severity: 'medium', confidence: 'medium', exts: PY,
    pattern: /\bDEBUG\s*=\s*True\b|\.run\s*\([^)]*debug\s*=\s*True/,
    why: 'Debug pages show source code, settings and sometimes an interactive console to anyone who triggers an error.',
    fix: 'Read DEBUG from the environment and default it to False in production.',
  },
  {
    id: 'py-verify-false', title: 'TLS certificate checking turned off', severity: 'high', confidence: 'high', exts: PY,
    pattern: /\bverify\s*=\s*False\b/,
    why: 'The request accepts any certificate, so anyone on the network path can read and change it.',
    fix: 'Remove verify=False. For a private CA, pass verify="/path/to/ca.pem".',
  },
  {
    id: 'py-weak-hash', title: 'MD5 or SHA-1 used', severity: 'low', confidence: 'medium', exts: PY,
    pattern: /hashlib\.(?:md5|sha1)\s*\(/,
    why: 'Both are broken for security uses. They are fine for checksums, not for passwords or signatures.',
    fix: 'For passwords use bcrypt, scrypt or argon2. For other hashing use SHA-256 or better.',
  },
  {
    id: 'py-predictable-random', title: 'random module used for a secret value', severity: 'medium', confidence: 'medium', exts: PY,
    pattern: /\brandom\.(?:random|randint|choice|choices|getrandbits)\s*\(/,
    filter: (line) => INPUT_WORDS.test(line),
    why: 'The random module is predictable. Tokens and codes made with it can be guessed.',
    fix: 'Use the secrets module: secrets.token_urlsafe().',
  },
  {
    id: 'py-template-unsafe', title: 'Template output marked safe', severity: 'medium', confidence: 'medium', exts: PY,
    pattern: /\b(?:render_template_string|mark_safe)\s*\(/,
    why: 'render_template_string with user input allows template injection, and mark_safe turns off escaping for its value.',
    fix: 'Use render_template with a file, and escape values. Mark content safe only when you wrote it.',
  },
  {
    id: 'py-mktemp', title: 'tempfile.mktemp is race-prone', severity: 'low', confidence: 'high', exts: PY,
    pattern: /\btempfile\.mktemp\s*\(/,
    why: 'Another process can create the file between the name being chosen and it being opened.',
    fix: 'Use tempfile.mkstemp or NamedTemporaryFile.',
  },

  // ---------------------------------------------------------------------- PHP
  {
    id: 'php-eval', title: 'eval() runs a string as code', severity: 'high', confidence: 'medium', exts: PHP,
    pattern: /(?<![.\w>:$])eval\s*\(/,
    why: 'If any part of the string comes from a user, they can run their own code on the server.',
    fix: 'Remove eval. Use data formats (JSON) and normal functions.',
  },
  {
    id: 'php-sql-injection', title: 'SQL built from request data or variables', severity: 'critical', confidence: 'medium', exts: PHP,
    pattern: new RegExp(
      '(?:\\b(?:mysql_query|mysqli_query|pg_query)\\s*\\([^;]*\\$_(?:GET|POST|REQUEST|COOKIE)\\b|->query\\s*\\([^;]*\\$_(?:GET|POST|REQUEST|COOKIE)\\b|"\\s*' + SQL + '[^"]*\\$[A-Za-z_]|["\']\\s*' + SQL + '[^"\']*["\']\\s*\\.\\s*\\$)',
      'i',
    ),
    why: 'Values placed inside the SQL text can change the query (SQL injection): reading or deleting data, or logging in without a password.',
    fix: 'Use prepared statements: $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);',
  },
  {
    id: 'php-xss-echo', title: 'Request data printed without escaping', severity: 'high', confidence: 'medium', exts: PHP,
    pattern: /\b(?:echo|print)\b[^;]*\$_(?:GET|POST|REQUEST|COOKIE)\b/,
    filter: (line) => !/htmlspecialchars|htmlentities|intval|\(int\)|esc_html|esc_attr|json_encode/i.test(line),
    why: 'Printing a request value as is lets an attacker add script to the page (cross-site scripting).',
    fix: 'Wrap output in htmlspecialchars($value, ENT_QUOTES, "UTF-8"), or use a template engine that escapes by default.',
  },
  {
    id: 'php-file-include', title: 'include or require with request data', severity: 'critical', confidence: 'high', exts: PHP,
    pattern: /\b(?:include|require)(?:_once)?\b[^;]*\$_(?:GET|POST|REQUEST|COOKIE)\b/,
    why: 'An attacker picks which file runs. That can expose local files or, in some setups, run code from another server.',
    fix: 'Never build the path from input. Map a short name to a fixed file from an allow-list.',
  },
  {
    id: 'php-command-injection', title: 'Shell command with request data', severity: 'critical', confidence: 'high', exts: PHP,
    pattern: /\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE)\b/,
    why: 'A request value in a shell command lets an attacker run their own commands on the server.',
    fix: 'Avoid shelling out. If you must, validate against a fixed list and wrap each argument in escapeshellarg().',
  },
  {
    id: 'php-unserialize', title: 'unserialize() on request data', severity: 'critical', confidence: 'high', exts: PHP,
    pattern: /\bunserialize\s*\([^;]*\$_(?:GET|POST|REQUEST|COOKIE)\b/,
    why: 'Crafted serialized data can trigger code execution through existing classes (object injection).',
    fix: 'Use json_decode for data from users.',
  },
  {
    id: 'php-extract-request', title: 'extract() on request data', severity: 'high', confidence: 'high', exts: PHP,
    pattern: /\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/,
    why: 'It lets a request overwrite any variable in scope, including flags like $is_admin.',
    fix: 'Read the specific fields you need from the request.',
  },
  {
    id: 'php-md5-password', title: 'Password hashed with MD5 or SHA-1', severity: 'high', confidence: 'medium', exts: PHP,
    pattern: /\b(?:md5|sha1)\s*\([^)]*pass/i,
    why: 'These hashes are fast to crack. A leaked database gives up most passwords quickly.',
    fix: 'Use password_hash() and password_verify().',
  },
  {
    id: 'php-phpinfo', title: 'phpinfo() call', severity: 'medium', confidence: 'high', exts: PHP,
    pattern: /\bphpinfo\s*\(/,
    why: 'It prints server paths, versions and settings, which help an attacker.',
    fix: 'Remove it before deploying.',
  },
  {
    id: 'php-display-errors', title: 'display_errors turned on', severity: 'low', confidence: 'medium', exts: PHP,
    pattern: /ini_set\s*\(\s*["']display_errors["']\s*,\s*["']?(?:1|on|true)["']?/i,
    why: 'Error messages reveal file paths and query text to visitors.',
    fix: 'Turn it off in production and log errors to a file instead.',
  },

  // ---------------------------------------------------------- Markup and config
  {
    id: 'html-http-script', title: 'Script loaded over plain HTTP', severity: 'medium', confidence: 'high', exts: MARKUP,
    pattern: /<script\b[^>]*\bsrc\s*=\s*["']http:\/\//i,
    why: 'Anyone on the network path can swap the file and run their code on your page.',
    fix: 'Load it over https:// or host the file yourself.',
  },
  {
    id: 'html-form-http', title: 'Form posts to a plain HTTP address', severity: 'medium', confidence: 'high', exts: MARKUP,
    pattern: /<form\b[^>]*\baction\s*=\s*["']http:\/\//i,
    why: 'Everything typed into the form is sent without encryption.',
    fix: 'Use an https:// action or a relative path on an HTTPS site.',
  },
  {
    id: 'html-no-sri', title: 'Third-party script without an integrity hash', severity: 'low', confidence: 'medium', exts: MARKUP,
    pattern: /<script\b[^>]*\bsrc\s*=\s*["']https:\/\/(?!(?:localhost|127\.0\.0\.1))[^"']+["'][^>]*>/i,
    filter: (line) => !/\bintegrity\s*=/i.test(line),
    why: 'If that host is compromised, so is your page. An integrity attribute makes the browser refuse a changed file.',
    fix: 'Add integrity="sha384-..." and crossorigin="anonymous", or host the file yourself. Skip for files the vendor changes in place.',
  },
  {
    id: 'cfg-directory-listing', title: 'Directory listing enabled', severity: 'medium', confidence: 'high', exts: ['conf', 'htaccess', 'config', 'cfg', 'ini'],
    pattern: /Options\s+\+?Indexes\b|\bautoindex\s+on\b/i,
    why: 'Visitors can browse and download every file in the folder, including ones you never linked.',
    fix: 'Use Options -Indexes (Apache) or autoindex off (nginx).',
  },
  {
    id: 'cfg-cors-wildcard', title: 'CORS allows any origin', severity: 'low', confidence: 'medium',
    pattern: /origin\s*:\s*["']\*["']|Access-Control-Allow-Origin["']?\s*[,:]?\s*["']?\*/i,
    why: 'Any website can read responses from this endpoint. Harmless for public data, a problem for anything tied to a login.',
    fix: 'Allow a fixed list of origins instead of *. Never combine a wildcard or reflected origin with credentials.',
  },
];

/** Rules that look at a whole file rather than a line. Implemented in filechecks.js. */
export const FILE_CHECKS = [
  {
    id: 'file-env-committed', title: 'Environment file with values in the upload', severity: 'high', confidence: 'high',
    why: '.env files hold passwords and keys. If it is in the folder you deploy or share, it can be copied or served.',
    fix: 'Keep .env out of version control (.gitignore) and out of the web root. Share an .env.example with empty values. Rotate anything that was in this file.',
  },
  {
    id: 'file-docker-root', title: 'Container runs as root', severity: 'low', confidence: 'medium',
    why: 'If the app is compromised, the attacker has root inside the container, which makes escaping it easier.',
    fix: 'Add a USER line for an unprivileged user before the CMD.',
  },
  {
    id: 'file-npm-install-script', title: 'Install script downloads and runs code', severity: 'medium', confidence: 'medium',
    why: 'Piping a download into a shell runs whatever the server sends at install time.',
    fix: 'Download, verify a checksum, then run. Or vendor the script.',
  },
  {
    id: 'file-npm-unpinned', title: 'Dependency version is not pinned', severity: 'medium', confidence: 'high',
    why: '"*" and "latest" install whatever is newest, including a version published by an attacker who took over the package.',
    fix: 'Use a version range such as ^1.2.3 and commit a lockfile.',
  },
  {
    id: 'file-npm-url-dependency', title: 'Dependency comes from a URL or Git branch', severity: 'medium', confidence: 'high',
    why: 'The code behind a URL or branch can change without a version bump, and plain http can be tampered with.',
    fix: 'Depend on a published version, or pin a Git dependency to a commit hash.',
  },
  {
    id: 'file-no-lockfile', title: 'No lockfile found', severity: 'low', confidence: 'medium',
    why: 'Without a lockfile, installs can pick up different (possibly compromised) versions on each machine.',
    fix: 'Commit package-lock.json, yarn.lock or pnpm-lock.yaml.',
  },
  {
    id: 'file-pip-insecure-index', title: 'Python packages fetched over plain HTTP', severity: 'medium', confidence: 'high',
    why: 'Packages downloaded over HTTP, or from a host marked trusted, can be replaced in transit.',
    fix: 'Use https:// package indexes and remove --trusted-host.',
  },
  {
    id: 'file-pip-unpinned', title: 'Python dependencies are not pinned', severity: 'low', confidence: 'medium',
    why: 'Unpinned requirements install different versions over time, so a bad release reaches you without any change in your code.',
    fix: 'Pin exact versions (package==1.2.3) or use a lock tool such as pip-tools or poetry.',
  },
];

/** Synthetic rule shown in the catalog for OSV-based dependency findings. */
export const CVE_RULE = {
  id: 'cve-known',
  title: 'Known vulnerability in a dependency',
  severity: 'high',
  confidence: 'high',
  why: 'A package version in your lockfile or requirements is listed in the OSV vulnerability database.',
  fix: 'Upgrade the package to a fixed version and refresh the lockfile.',
};

export function ruleCatalog() {
  const lang = (exts) => (!exts ? 'any' : exts === JS ? 'JavaScript' : exts === PY ? 'Python' : exts === PHP ? 'PHP' : exts === MARKUP ? 'HTML and templates' : exts.join(', '));
  return [
    ...RULES.map(({ id, title, severity, confidence, exts }) => ({ id, title, severity, confidence, applies: lang(exts) })),
    ...FILE_CHECKS.map(({ id, title, severity, confidence }) => ({ id, title, severity, confidence, applies: 'whole file' })),
    { id: CVE_RULE.id, title: CVE_RULE.title, severity: CVE_RULE.severity, confidence: CVE_RULE.confidence, applies: 'dependencies (OSV)' },
  ];
}