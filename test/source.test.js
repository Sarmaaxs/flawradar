import test from 'node:test';
import assert from 'node:assert/strict';
import { makeZip } from './helpers/zipwriter.js';

process.env.FLAWRADAR_DB = ':memory:';
const { analyzeFiles, redactSecrets, ruleCatalog } = await import('../server/source/analyze.js');
const { readZip } = await import('../server/source/zip.js');
const { normalizePath, skipReason } = await import('../server/source/paths.js');
const { RULES } = await import('../server/source/rules.js');

const limits = { maxEntries: 1000, maxFileBytes: 512 * 1024, maxTotalBytes: 5 * 1024 * 1024 };

// Build a secret-looking value at run time so this file does not hold a real-format key.
const awsKey = `AKIA${'ABCDEFGHIJ012345'}`;
const ghToken = `ghp_${'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'}`;

const hit = (result, id) => result.findings.filter((f) => f.ruleId === id);
const scan = (path, content) => analyzeFiles([{ path, content }]);

async function assertFlags(path, line, id) {
  const r = await scan(path, line);
  assert.equal(hit(r, id).length, 1, `${id} should match: ${line}`);
}
async function assertClean(path, line, id) {
  const r = await scan(path, line);
  assert.equal(hit(r, id).length, 0, `${id} should not match: ${line}`);
}

test('every rule has an id, explanation and fix, and ids are unique', () => {
  const ids = RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const r of RULES) {
    assert.ok(r.title && r.why && r.fix && r.severity && r.confidence && r.pattern instanceof RegExp, r.id);
    assert.ok(['critical', 'high', 'medium', 'low'].includes(r.severity), r.id);
  }
  assert.ok(ruleCatalog().length > 50);
});

test('secrets are found and masked in the output', async () => {
  const r = await analyzeFiles([
    { path: 'config/aws.js', content: `const key = "${awsKey}";\n` },
    { path: 'deploy.sh.txt', content: `token=${ghToken}\n` },
    { path: 'src/db.js', content: 'const pw = "postgres://admin:Sup3rS3cretPw@db.example.com/app";\n' },
    { path: 'src/auth.js', content: 'const password = "correct-horse-battery";\n' },
    { path: 'src/jwt.js', content: 'const t = jwt.sign({ id: 1 }, "my-signing-secret-value");\n' },
    { path: 'key.txt', content: '-----BEGIN RSA PRIVATE KEY-----\nabc\n' },
  ]);
  assert.equal(hit(r, 'secret-aws-key').length, 1);
  assert.equal(hit(r, 'secret-github-token').length, 1);
  assert.equal(hit(r, 'secret-db-url').length, 1);
  assert.equal(hit(r, 'secret-hardcoded').length, 1);
  assert.equal(hit(r, 'secret-jwt-literal').length, 1);
  assert.equal(hit(r, 'secret-private-key').length, 1);
  const out = JSON.stringify(r);
  for (const secret of [awsKey, ghToken, 'Sup3rS3cretPw', 'correct-horse-battery', 'my-signing-secret-value']) {
    assert.ok(!out.includes(secret), `output must not contain ${secret}`);
  }
  assert.ok(out.includes('AKI***'));
});

test('hard-coded secret rule ignores placeholders, env lookups and test files', async () => {
  for (const line of [
    'const password = process.env.DB_PASSWORD;',
    'password = os.environ["PASSWORD"]',
    'const apiKey = "YOUR_API_KEY_HERE";',
    'password: "changeme123"',
    'const secret = "xxxxxxxxxxxx";',
    'const password = "aaaaaaaaaaaa";',
    'passwordHash = "abcdefghijkl"',
  ]) {
    await assertClean('src/a.js', line, 'secret-hardcoded');
  }
  const r = await analyzeFiles([{ path: 'test/auth.test.js', content: 'const password = "correct-horse-battery";' }]);
  assert.equal(hit(r, 'secret-hardcoded').length, 0);
});

test('JavaScript rules', async () => {
  await assertFlags('a.js', 'const x = eval(userInput);', 'js-eval');
  await assertClean('a.js', 'model.eval();', 'js-eval');
  await assertClean('a.js', '// eval(userInput) is dangerous', 'js-eval');
  await assertFlags('a.js', 'el.innerHTML = "<b>" + name + "</b>";', 'js-innerhtml');
  await assertClean('a.js', 'el.innerHTML = "";', 'js-innerhtml');
  await assertClean('a.js', 'el.innerHTML = "<hr>";', 'js-innerhtml');
  await assertClean('a.js', 'if (el.innerHTML === "x") {}', 'js-innerhtml');
  await assertFlags('a.js', 'document.write(x)', 'js-document-write');
  await assertFlags('a.jsx', '<div dangerouslySetInnerHTML={{ __html: html }} />', 'js-react-dangerous-html');
  await assertFlags('a.js', 'exec(`ls ${dir}`, cb)', 'js-command-injection');
  await assertFlags('a.js', 'child_process.exec("ls " + dir, cb)', 'js-command-injection');
  await assertClean('a.js', 'execFile("ls", [dir], cb)', 'js-command-injection');
  await assertFlags('a.js', 'spawn(cmd, args, { shell: true })', 'js-spawn-shell');
  await assertFlags('a.js', 'db.query(`SELECT * FROM users WHERE id = ${id}`)', 'js-sql-template');
  await assertClean('a.js', 'db.query("SELECT * FROM users WHERE id = $1", [id])', 'js-sql-template');
  await assertFlags('a.js', 'const q = "SELECT * FROM users WHERE name = \'" + name + "\'";', 'js-sql-concat');
  await assertFlags('a.js', "const q = 'DELETE FROM t WHERE id = ' + id;", 'js-sql-concat');
  await assertClean('a.js', 'const q = "SELECT * FROM users WHERE id = $1";', 'js-sql-concat');
  await assertFlags('a.js', 'fs.readFile(req.query.file, cb)', 'js-path-traversal');
  await assertFlags('a.js', 'res.redirect(req.query.next)', 'js-open-redirect');
  await assertFlags('a.js', 'https.request({ rejectUnauthorized: false })', 'js-tls-verification-off');
  await assertFlags('a.js', 'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"', 'js-tls-verification-off');
  await assertFlags('a.js', 'crypto.createHash("md5").update(p)', 'js-weak-hash');
  await assertFlags('a.js', 'const token = Math.random().toString(36)', 'js-predictable-random');
  await assertClean('a.js', 'const x = Math.random() * 10', 'js-predictable-random');
  await assertFlags('a.js', 'cookie: { httpOnly: false }', 'js-cookie-flags-off');
  await assertFlags('a.js', 'jwt.verify(t, k, { algorithms: ["none"] })', 'js-jwt-none');
  await assertFlags('a.js', 'localStorage.setItem("authToken", t)', 'js-token-in-localstorage');
});

test('Python rules', async () => {
  await assertFlags('a.py', 'result = eval(request.args["x"])', 'py-eval-exec');
  await assertClean('a.py', 'model.eval()', 'py-eval-exec');
  await assertClean('a.py', 'cursor.execute(sql, params)', 'py-eval-exec');
  await assertFlags('a.py', 'data = pickle.loads(blob)', 'py-pickle');
  await assertFlags('a.py', 'cfg = yaml.load(f)', 'py-yaml-load');
  await assertClean('a.py', 'cfg = yaml.load(f, Loader=yaml.SafeLoader)', 'py-yaml-load');
  await assertClean('a.py', 'cfg = yaml.safe_load(f)', 'py-yaml-load');
  await assertFlags('a.py', 'subprocess.run(cmd, shell=True)', 'py-shell-true');
  await assertFlags('a.py', 'os.system("ping " + host)', 'py-os-system');
  await assertFlags('a.py', 'cur.execute(f"SELECT * FROM users WHERE id = {uid}")', 'py-sql-format');
  await assertFlags('a.py', 'cur.execute("SELECT * FROM users WHERE id = %s" % uid)', 'py-sql-format');
  await assertFlags('a.py', 'cur.execute("SELECT * FROM t WHERE a = {}".format(a))', 'py-sql-format');
  await assertClean('a.py', 'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))', 'py-sql-format');
  await assertFlags('settings.py', 'DEBUG = True', 'py-debug-on');
  await assertFlags('a.py', 'requests.get(url, verify=False)', 'py-verify-false');
  await assertFlags('a.py', 'token = random.choice(chars)', 'py-predictable-random');
  await assertFlags('a.py', 'return render_template_string(tpl)', 'py-template-unsafe');
});

test('PHP rules', async () => {
  await assertFlags('a.php', '$r = mysqli_query($c, "SELECT * FROM u WHERE id=" . $_GET["id"]);', 'php-sql-injection');
  await assertFlags('a.php', '$q = "SELECT * FROM users WHERE name = \'$name\'";', 'php-sql-injection');
  await assertClean('a.php', '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");', 'php-sql-injection');
  await assertFlags('a.php', 'echo "Hello " . $_GET["name"];', 'php-xss-echo');
  await assertClean('a.php', 'echo htmlspecialchars($_GET["name"]);', 'php-xss-echo');
  await assertFlags('a.php', 'include($_GET["page"] . ".php");', 'php-file-include');
  await assertFlags('a.php', 'system("ping " . $_POST["host"]);', 'php-command-injection');
  await assertFlags('a.php', '$o = unserialize($_COOKIE["data"]);', 'php-unserialize');
  await assertFlags('a.php', 'extract($_POST);', 'php-extract-request');
  await assertFlags('a.php', '$h = md5($password);', 'php-md5-password');
  await assertFlags('a.php', 'phpinfo();', 'php-phpinfo');
  await assertFlags('a.php', 'eval($code);', 'php-eval');
  await assertClean('a.php', '$this->eval($code);', 'php-eval');
});

test('Java security rules', async () => {
  await assertFlags('App.java', 'Object value = input.readObject();', 'java-unsafe-deserialization');
  await assertFlags('App.java', 'statement.executeQuery("SELECT * FROM users WHERE id = " + id);', 'java-sql-concat');
  await assertClean('App.java', 'PreparedStatement ps = db.prepareStatement("SELECT * FROM users WHERE id = ?");', 'java-sql-concat');
  await assertFlags('App.java', 'MessageDigest.getInstance("SHA-1");', 'java-weak-hash');
  await assertFlags('App.java', 'String token = new Random().nextInt() + "";', 'java-predictable-random');
  await assertClean('App.java', 'SecureRandom tokenGenerator = new SecureRandom();', 'java-predictable-random');
});

test('markup and config rules', async () => {
  await assertFlags('a.html', '<script src="http://cdn.example.net/a.js"></script>', 'html-http-script');
  await assertFlags('a.html', '<form action="http://example.com/login" method="post">', 'html-form-http');
  await assertFlags('a.html', '<script src="https://cdn.example.net/a.js"></script>', 'html-no-sri');
  await assertClean('a.html', '<script src="https://cdn.example.net/a.js" integrity="sha384-x" crossorigin="anonymous"></script>', 'html-no-sri');
  await assertClean('a.html', '<script src="/local.js"></script>', 'html-no-sri');
  await assertFlags('.htaccess', 'Options +Indexes', 'cfg-directory-listing');
  await assertFlags('nginx.conf', 'autoindex on;', 'cfg-directory-listing');
  await assertFlags('server.js', 'app.use(cors({ origin: "*" }))', 'cfg-cors-wildcard');
  await assertFlags('App.vue', '<div v-html="body"></div>', 'js-vue-vhtml');
});

test('rules respect the language of the file', async () => {
  // PHP rule on a JS file, JS rule on a Python file: no matches.
  assert.equal((await scan('a.js', 'phpinfo();')).findings.length, 0);
  assert.equal((await scan('a.py', 'document.write(x)')).findings.length, 0);
});

test('file-level checks', async () => {
  const r = await analyzeFiles([
    { path: '.env', content: 'DB_PASSWORD=hunter2hunter2\nDEBUG=true\n' },
    { path: '.env.example', content: 'DB_PASSWORD=\n' },
    { path: 'Dockerfile', content: 'FROM node:22\nCOPY . .\nCMD ["node","a.js"]\n' },
    { path: 'ok/Dockerfile', content: 'FROM node:22\nUSER node\nCMD ["node","a.js"]\n' },
    {
      path: 'package.json',
      content: JSON.stringify({
        dependencies: { lodash: '*', express: '^4.18.0', mine: 'github:someone/repo', pinned: 'github:someone/repo#0123456789abcdef0123456789abcdef01234567', tarball: 'http://example.com/x.tgz' },
        scripts: { postinstall: 'curl -s https://example.com/i.sh | sh', test: 'node --test' },
      }, null, 2),
    },
    { path: 'requirements.txt', content: 'flask\nrequests==2.31.0\n--trusted-host pypi.example.com\n' },
  ]);
  const env = hit(r, 'file-env-committed');
  assert.equal(env.length, 1);
  assert.equal(env[0].file, '.env');
  assert.ok(!JSON.stringify(r).includes('hunter2hunter2'));
  assert.deepEqual(hit(r, 'file-docker-root').map((f) => f.file), ['Dockerfile']);
  assert.equal(hit(r, 'file-npm-unpinned').length, 1);
  assert.equal(hit(r, 'file-npm-url-dependency').length, 2); // github branch + http tarball, not the commit-pinned one
  assert.equal(hit(r, 'file-npm-install-script').length, 1);
  assert.equal(hit(r, 'file-no-lockfile').length, 1);
  assert.equal(hit(r, 'file-pip-unpinned').length, 1);
  assert.equal(hit(r, 'file-pip-insecure-index').length, 1);

  const locked = await analyzeFiles([
    { path: 'package.json', content: '{"dependencies":{"a":"^1.0.0"}}' },
    { path: 'package-lock.json', content: '{}' },
  ]);
  assert.equal(hit(locked, 'file-no-lockfile').length, 0);
});

test('skips dependencies, generated files, binaries and oversized files, and says so', async () => {
  const r = await analyzeFiles([
    { path: 'node_modules/x/index.js', content: 'eval(x)' },
    { path: 'vendor/lib.php', content: 'eval($x);' },
    { path: 'app.min.js', content: 'eval(x)' },
    { path: 'logo.png', content: 'eval(x)' },
    { path: 'bin.js', content: 'eval(x)\0\0' },
    { path: 'big.js', content: `eval(x)\n${'a'.repeat(600 * 1024)}` },
    { path: '../escape.js', content: 'eval(x)' },
    { path: 'src/ok.js', content: 'eval(x)' },
  ]);
  assert.equal(r.stats.filesScanned, 1);
  assert.deepEqual(hit(r, 'js-eval').map((f) => f.file), ['src/ok.js']);
  assert.match(r.notices.join(' '), /Skipped folders: node_modules, vendor/);
});

test('minified-length lines are skipped, and per-rule caps keep output short', async () => {
  const long = `eval(x);${'a'.repeat(1200)}`;
  const many = Array.from({ length: 40 }, () => 'eval(x);').join('\n');
  const r = await analyzeFiles([{ path: 'a.js', content: long }, { path: 'b.js', content: many }]);
  assert.equal(hit(r, 'js-eval').filter((f) => f.file === 'a.js').length, 0);
  assert.equal(hit(r, 'js-eval').filter((f) => f.file === 'b.js').length, 5);
  assert.match(r.notices.join(' '), /very long lines/);
});

test('findings are sorted most severe first and summarised', async () => {
  const r = await analyzeFiles([{ path: 'a.js', content: `crypto.createHash("md5");\nconst k = "${awsKey}";\n` }]);
  assert.deepEqual(r.findings.map((f) => f.severity), ['critical', 'low']);
  assert.equal(r.summary.critical, 1);
  assert.equal(r.summary.low, 1);
});

test('rules run in linear time on hostile lines', async () => {
  const lines = [
    `db.query("${'SELECT '.repeat(100)}`,
    `${'"a" + '.repeat(150)}x`,
    `x = "${'a'.repeat(900)}`,
    `password${' '.repeat(900)}=`,
    `<script ${'src="'.repeat(200)}`,
    `echo ${'$_GET '.repeat(150)}`,
  ];
  const started = Date.now();
  for (const [path, line] of [['a.js', lines[0]], ['a.js', lines[1]], ['a.py', lines[2]], ['a.js', lines[3]], ['a.html', lines[4]], ['a.php', lines[5]]]) {
    await scan(path, line);
  }
  assert.ok(Date.now() - started < 1000, `took ${Date.now() - started}ms`);
});

test('redactSecrets masks known formats', () => {
  assert.equal(redactSecrets(`k=${awsKey}`), 'k=AKI***');
  assert.ok(!redactSecrets(`t ${ghToken} t`).includes(ghToken));
});

test('paths are normalised and traversal is refused', () => {
  assert.equal(normalizePath('./src//a.js'), 'src/a.js');
  assert.equal(normalizePath('\\src\\a.js'), 'src/a.js');
  assert.equal(normalizePath('/abs/a.js'), 'abs/a.js');
  assert.equal(normalizePath('../a.js'), null);
  assert.equal(normalizePath('a/../../b.js'), null);
  assert.equal(normalizePath(''), null);
  assert.equal(normalizePath(5), null);
  assert.equal(skipReason('a/node_modules/b.js'), 'folder:node_modules');
  assert.equal(skipReason('.env.production'), null);
  assert.equal(skipReason('img/logo.png'), 'type');
});

// ----------------------------------------------------------------------- zip

test('zip: reads stored and deflated entries, skips folders and dependencies', () => {
  const zip = makeZip([
    { name: 'site/', data: '', method: 0 },
    { name: 'site/app.js', data: 'eval(x)\n' },
    { name: 'site/raw.php', data: '<?php phpinfo();', method: 0 },
    { name: 'site/node_modules/dep/index.js', data: 'eval(x)' },
    { name: 'site/logo.png', data: 'x' },
  ]);
  const { files, skipped } = readZip(zip, limits);
  assert.deepEqual(files.map((f) => f.path).sort(), ['site/app.js', 'site/raw.php']);
  assert.equal(files.find((f) => f.path === 'site/app.js').content, 'eval(x)\n');
  assert.deepEqual(skipped.map((s) => s.reason).sort(), ['folder:node_modules', 'type']);
});

test('zip: names that climb out of the root are dropped', () => {
  const { files, skipped } = readZip(makeZip([{ name: '../../evil.js', data: 'x' }, { name: 'ok.js', data: 'x' }]), limits);
  assert.deepEqual(files.map((f) => f.path), ['ok.js']);
  assert.equal(skipped[0].reason, 'path');
});

test('zip: a decompression bomb is stopped by the output cap', () => {
  const bomb = Buffer.alloc(50 * 1024 * 1024, 'a'); // deflates to about 50 KB
  const zip = makeZip([{ name: 'bomb.js', data: bomb, declaredSize: 100 }, { name: 'ok.js', data: 'x' }]);
  assert.ok(zip.length < 200_000);
  const { files, skipped } = readZip(zip, limits);
  assert.deepEqual(files.map((f) => f.path), ['ok.js']);
  assert.equal(skipped.find((s) => s.path === 'bomb.js').reason, 'large');
});

test('zip: declared size over the file limit is skipped without inflating', () => {
  const zip = makeZip([{ name: 'big.js', data: 'x', declaredSize: 10 * 1024 * 1024 }]);
  assert.equal(readZip(zip, limits).skipped[0].reason, 'large');
});

test('zip: encrypted entries and total size limit', () => {
  const enc = readZip(makeZip([{ name: 'a.js', data: 'x', flags: 1 }]), limits);
  assert.equal(enc.skipped[0].reason, 'encrypted');
  const many = makeZip([1, 2, 3].map((n) => ({ name: `f${n}.js`, data: 'a'.repeat(400) })));
  const capped = readZip(many, { ...limits, maxTotalBytes: 900 });
  assert.equal(capped.files.length, 2);
  assert.match(capped.notices[0], /Stopped reading the zip/);
});

test('zip: garbage and damaged archives are rejected cleanly', () => {
  for (const bytes of [Buffer.alloc(0), Buffer.from('not a zip at all, just text'), Buffer.alloc(100)]) {
    assert.throws(() => readZip(bytes, limits), (err) => err.code === 'bad_zip');
  }
  const good = makeZip([{ name: 'a.js', data: 'hello' }]);
  const cut = Buffer.from(good);
  cut.writeUInt32LE(0xfffffff0, cut.length - 6); // central directory offset beyond the file
  assert.throws(() => readZip(cut, limits), (err) => err.code === 'bad_zip');
  assert.throws(() => readZip(makeZip(Array.from({ length: 5 }, (_, i) => ({ name: `f${i}.js`, data: 'x' }))), { ...limits, maxEntries: 3 }), (err) => err.code === 'bad_zip');
});

test('zip contents flow through the analyser', async () => {
  const zip = makeZip([{ name: 'app/index.php', data: '<?php\necho $_GET["q"];\n' }]);
  const { files, skipped, notices } = readZip(zip, limits);
  const r = await analyzeFiles(files, { skipped, notices });
  assert.equal(hit(r, 'php-xss-echo')[0].file, 'app/index.php');
  assert.equal(hit(r, 'php-xss-echo')[0].line, 2);
});