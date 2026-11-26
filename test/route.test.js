import test from 'node:test';
import assert from 'node:assert/strict';
import { parseTracerouteOutput, summarizeRoute } from '../server/scanner/route.js';

test('traceroute parser extracts ordered IPv4 hops, RTT samples and timeouts', () => {
  const hops = parseTracerouteOutput([
    'traceroute to 203.0.113.8 (203.0.113.8), 12 hops max',
    ' 1  192.0.2.1  1.20 ms',
    ' 2  *',
    ' 3  203.0.113.8  8.40 ms',
  ].join('\n'), '203.0.113.8');
  assert.equal(hops.length, 3);
  assert.deepEqual(hops[0].addresses, ['192.0.2.1']);
  assert.equal(hops[1].lossPercent, 100);
  assert.equal(hops[2].reached, true);
});

test('traceroute parser accepts IPv6 and ignores malformed or out-of-range rows', () => {
  const hops = parseTracerouteOutput(' 1  2001:4860:4860::8888  2.5 ms\n 99  192.0.2.1  1 ms\n nope', '2001:4860:4860::8888');
  assert.equal(hops.length, 1);
  assert.deepEqual(hops[0].addresses, ['2001:4860:4860::8888']);
});

test('route summary calculates response rate, mean RTT and variation', () => {
  const hops = parseTracerouteOutput(' 1  192.0.2.1  2.0 ms\n 2  203.0.113.8  6.0 ms', '203.0.113.8');
  const summary = summarizeRoute(hops, '203.0.113.8');
  assert.equal(summary.destinationReached, true);
  assert.equal(summary.hopsObserved, 2);
  assert.equal(summary.responseRatePercent, 100);
  assert.equal(summary.meanRttMs, 4);
  assert.equal(summary.meanAbsoluteRttVariationMs, 4);
});
