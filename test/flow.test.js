import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeFiles } from '../server/source/analyze.js';
import { entropy, flowFindings, secretFindings } from '../server/source/flow.js';

const flow = (ext, code) => flowFindings(`a.${ext}`, ext, code.split('\n'));
const ids = (list) => list.map((f) => f.ruleId).sort();

test('JS: request data followed into a SQL string, a shell, eval and the page', () => {
  const found = flow('js', [
    'app.get("/u", (req, res) => {',
    '  const id = req.query.id;',
    '  const where = "id = " + id;',
    '  db.query("SELECT * FROM users WHERE " + where);',
    '  exec(`ls ${req.body.dir}`);',
    '  const { code } = req.body;',
    '  eval(code);',
    '  el.innerHTML = id;',
    '});',
  ].join('\n'));
  assert.deepEqual(ids(found), ['flow-eval', 'flow-html', 'flow-shell', 'flow-sql']);
  const sql = found.find((f) => f.ruleId === 'flow-sql');
  assert.equal(sql.line, 4);
  assert.match(sql.why, /line 2/);
});

test('JS: cleaned or parameterised values are left alone', () => {
  const found = flow('js', [
    'const id = parseInt(req.query.id, 10);',
    'db.query("SELECT * FROM users WHERE id = " + id);',
    'const name = req.body.name;',
    'db.query("SELECT * FROM users WHERE name = ?", [name]);',
    'let x = req.query.x;',
    'x = "constant";',
    'eval(x);',
    'const safe = encodeURIComponent(req.query.q);',
    'res.redirect("/search?q=" + safe);',
  ].join('\n'));
  assert.deepEqual(found, []);
});

test('JS: path, request, redirect and module sinks', () => {
  const found = flow('js', [
    'const f = req.query.file;',
    'fs.readFile(f, cb);',
    'const target = req.query.url;',
    'fetch(target);',
    'res.redirect(req.query.next);',
    'require(req.body.mod);',
  ].join('\n'));
  assert.deepEqual(ids(found), ['flow-path', 'flow-redirect', 'flow-require', 'flow-ssrf']);
});

test('Python and PHP are followed too', () => {
  const py = flow('py', [
    'uid = request.args.get("id")',
    'q = "SELECT * FROM t WHERE id = " + uid',
    'cur.execute(q)',
    'cur.execute(f"SELECT * FROM t WHERE id = {uid}")',
    'os.system("ping " + uid)',
    'safe = int(request.args.get("n"))',
    'cur.execute("SELECT %s" % safe)',
  ].join('\n'));
  assert.deepEqual(ids(py), ['flow-shell', 'flow-sql']);
  const php = flow('php', [
    '$id = $_GET["id"];',
    '$r = mysqli_query($db, "SELECT * FROM t WHERE id = $id");',
    'echo $id;',
    'include $page;',
    '$page = $_GET["p"];',
    'include $page;',
    '$n = intval($_GET["n"]);',
    'echo $n;',
  ].join('\n'));
  assert.deepEqual(ids(php), ['flow-include', 'flow-sql', 'flow-xss']);
});

test('lines already caught by a line rule are not reported twice', async () => {
  const r = await analyzeFiles([{ path: 'a.js', content: 'const id = req.query.id;\neval(id);\n' }]);
  assert.equal(r.findings.filter((f) => f.line === 2).length, 1);
});

test('secrets by randomness: real-looking values yes, placeholders and prose no', () => {
  const found = secretFindings('c.js', [
    'const apiToken = "k8Jd93LsPq2Zx7VbN1mQw4Re";',
    'const password = "correct-horse-battery";',
    'const secret = process.env.SECRET_KEY_VALUE_LONG;',
    'const api_key = "your_api_key_goes_here_12345";',
    'authUrl = "https://example.com/oauth/authorize";',
    'client_secret: "Zr3Tg8uHq1LpXc5VaB7nYd2K"',
  ]);
  assert.equal(found.length, 2);
  assert.match(found[0].snippet, /k8J\*\*\*/);
  assert.ok(!found[0].snippet.includes('Pq2Zx7'));
  assert.ok(entropy('aaaaaaaa') < 1 && entropy('k8Jd93LsPq2Zx7VbN1mQw4Re') > 4);
});

test('test folders are not scanned by the second pass', async () => {
  const r = await analyzeFiles([{ path: 'tests/a.test.js', content: 'const id = req.query.id;\neval(id);\n' }]);
  assert.equal(r.findings.filter((f) => f.ruleId.startsWith('flow-')).length, 0);
});
