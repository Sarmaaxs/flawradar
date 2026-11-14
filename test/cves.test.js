import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { collectPackages, lookupCves, runCveChecks } from '../server/source/cves.js';
import { analyzeFiles } from '../server/source/analyze.js';

const LOCK_V2 = JSON.stringify({
  name: 'demo',
  lockfileVersion: 2,
  requires: true,
  packages: {
    '': { name: 'demo', version: '1.0.0' },
    'node_modules/lodash': { version: '4.17.15' },
    'node_modules/left-pad': { version: '1.3.0' },
  },
});

const REQUIREMENTS = `
# comment
requests==2.19.1
Flask==1.0.2
django>=3.0
`;

describe('collectPackages', () => {
  test('reads package-lock.json v2 packages', () => {
    const { packages } = collectPackages([{ path: 'package-lock.json', content: LOCK_V2 }]);
    const names = packages.map((p) => p.name).sort();
    assert.deepEqual(names, ['left-pad', 'lodash']);
    assert.equal(packages.find((p) => p.name === 'lodash').version, '4.17.15');
    assert.equal(packages[0].ecosystem, 'npm');
  });

  test('reads pinned requirements.txt', () => {
    const { packages } = collectPackages([{ path: 'requirements.txt', content: REQUIREMENTS }]);
    assert.equal(packages.length, 2);
    assert.deepEqual(
      packages.map((p) => [p.name, p.version]).sort(),
      [
        ['flask', '1.0.2'],
        ['requests', '2.19.1'],
      ],
    );
    assert.equal(packages[0].ecosystem, 'PyPI');
  });

  test('falls back to package.json ranges when no lockfile', () => {
    const pkg = JSON.stringify({
      dependencies: { lodash: '^4.17.15', leftpad: 'latest' },
    });
    const { packages, notices } = collectPackages([{ path: 'package.json', content: pkg }]);
    assert.equal(packages.length, 1);
    assert.equal(packages[0].name, 'lodash');
    assert.equal(packages[0].version, '4.17.15');
    assert.ok(notices.some((n) => /No package-lock/.test(n)));
  });

  test('prefers lockfile over package.json', () => {
    const pkg = JSON.stringify({ dependencies: { lodash: '^9.0.0' } });
    const { packages } = collectPackages([
      { path: 'package.json', content: pkg },
      { path: 'package-lock.json', content: LOCK_V2 },
    ]);
    assert.ok(packages.some((p) => p.name === 'lodash' && p.version === '4.17.15'));
    assert.ok(!packages.some((p) => p.version === '9.0.0'));
  });
});

describe('lookupCves', () => {
  test('maps OSV hits into findings', async () => {
    const packages = [
      { name: 'lodash', version: '4.17.15', ecosystem: 'npm', file: 'package-lock.json', line: 1 },
    ];
    const fakeFetch = async (url) => {
      if (String(url).includes('querybatch')) {
        return {
          ok: true,
          json: async () => ({
            results: [{ vulns: [{ id: 'GHSA-xxxx-yyyy-zzzz' }] }],
          }),
        };
      }
      // detail hydration
      return {
        ok: true,
        json: async () => ({
          id: 'GHSA-xxxx-yyyy-zzzz',
          summary: 'Prototype pollution in lodash',
          aliases: ['CVE-2019-10744'],
          severity: [{ type: 'CVSS_V3', score: '9.8' }],
          affected: [
            {
              package: { name: 'lodash', ecosystem: 'npm' },
              ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
            },
          ],
        }),
      };
    };

    const { findings, checked } = await lookupCves(packages, { fetch: fakeFetch });
    assert.equal(checked, 1);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].ruleId, 'cve-known');
    assert.equal(findings[0].severity, 'critical');
    assert.equal(findings[0].cve, 'CVE-2019-10744');
    assert.match(findings[0].title, /CVE-2019-10744/);
    assert.match(findings[0].fix, /4\.17\.21/);
  });

  test('survives OSV errors with a notice', async () => {
    const packages = [
      { name: 'lodash', version: '4.17.15', ecosystem: 'npm', file: 'package-lock.json', line: 1 },
    ];
    const fakeFetch = async () => {
      throw new Error('network down');
    };
    const { findings, notices, checked } = await lookupCves(packages, { fetch: fakeFetch });
    assert.equal(findings.length, 0);
    assert.equal(checked, 0);
    assert.ok(notices.some((n) => /Could not reach|timed out/i.test(n)));
  });
});

describe('analyzeFiles integration', () => {
  test('CVE findings appear in the result when OSV returns hits', async () => {
    const fakeFetch = async (url) => {
      if (String(url).includes('querybatch')) {
        return {
          ok: true,
          json: async () => ({
            results: [{ vulns: [{ id: 'GHSA-test' }] }, { vulns: [] }],
          }),
        };
      }
      return {
        ok: true,
        json: async () => ({
          id: 'GHSA-test',
          summary: 'Test vuln',
          aliases: ['CVE-2020-0000'],
          severity: [{ type: 'CVSS_V3', score: '7.5' }],
          affected: [],
        }),
      };
    };

    const r = await analyzeFiles(
      [
        { path: 'src/app.js', content: 'console.log("hi");\n' },
        { path: 'package-lock.json', content: LOCK_V2 },
      ],
      { fetch: fakeFetch },
    );

    assert.ok(r.stats);
    assert.ok(Array.isArray(r.findings));
    assert.ok(Array.isArray(r.notices));
    assert.ok(r.findings.some((f) => f.ruleId === 'cve-known'));
    assert.ok(r.stats.packagesChecked >= 1);
  });
});

test('runCveChecks end-to-end with mock', async () => {
  const fakeFetch = async (url, init) => {
    if (String(url).includes('querybatch')) {
      const body = JSON.parse(init.body);
      assert.ok(body.queries.length >= 1);
      return {
        ok: true,
        json: async () => ({
          results: body.queries.map((q) =>
            q.package.name === 'lodash' ? { vulns: [{ id: 'GHSA-lodash' }] } : { vulns: [] },
          ),
        }),
      };
    }
    return {
      ok: true,
      json: async () => ({
        id: 'GHSA-lodash',
        summary: 'Old lodash',
        aliases: ['CVE-2019-10744'],
        severity: [{ type: 'CVSS_V3', score: '9.1' }],
        affected: [
          {
            package: { name: 'lodash', ecosystem: 'npm' },
            ranges: [{ type: 'SEMVER', events: [{ fixed: '4.17.21' }] }],
          },
        ],
      }),
    };
  };

  const result = await runCveChecks(
    [{ path: 'package-lock.json', content: LOCK_V2 }],
    { fetch: fakeFetch },
  );
  assert.ok(result.checked >= 1);
  assert.ok(result.findings.some((f) => f.ruleId === 'cve-known' && f.package === 'lodash'));
  assert.ok(result.findings.some((f) => f.cve === 'CVE-2019-10744'));
});
