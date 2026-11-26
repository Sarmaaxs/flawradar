import { spawn } from 'node:child_process';
import { access } from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import net from 'node:net';
import { isPublicIp, resolvePublic } from './net.js';

const MAX_HOPS = 12;
const PROBES_PER_HOP = 1;
const TIMEOUT_MS = 14_000;
const MAX_OUTPUT = 32_000;
const BINARIES = ['/usr/sbin/traceroute', '/usr/bin/traceroute', '/bin/traceroute', '/usr/local/bin/traceroute'];

export function parseTracerouteOutput(output, destination, probesPerHop = PROBES_PER_HOP) {
  const hops = [];
  for (const line of String(output || '').split(/\r?\n/)) {
    const row = /^\s*(\d+)\s+(.*)$/.exec(line);
    if (!row) continue;
    const ttl = Number(row[1]);
    if (!Number.isInteger(ttl) || ttl < 1 || ttl > MAX_HOPS) continue;
    const body = row[2];
    const candidates = body.match(/(?:\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F]*:[0-9a-fA-F:]{2,})/g) || [];
    const addresses = [...new Set(candidates.filter((ip) => net.isIP(ip)))].slice(0, 3);
    const rtts = [...body.matchAll(/(\d+(?:\.\d+)?)\s*ms\b/g)].map((m) => Number(m[1])).filter((n) => Number.isFinite(n) && n >= 0 && n <= 120_000).slice(0, probesPerHop);
    hops.push({
      ttl,
      addresses,
      rttsMs: rtts,
      probesSent: probesPerHop,
      probesAnswered: rtts.length,
      lossPercent: Math.round((1 - rtts.length / probesPerHop) * 100),
      reached: addresses.includes(destination),
    });
  }
  return hops.sort((a, b) => a.ttl - b.ttl).slice(0, MAX_HOPS);
}

export function summarizeRoute(hops, destination) {
  const samples = hops.flatMap((hop) => hop.rttsMs);
  const deltas = samples.slice(1).map((value, index) => Math.abs(value - samples[index]));
  const totalProbes = hops.reduce((sum, hop) => sum + hop.probesSent, 0);
  const answered = hops.reduce((sum, hop) => sum + hop.probesAnswered, 0);
  const mean = (values) => values.length ? Number((values.reduce((sum, value) => sum + value, 0) / values.length).toFixed(2)) : null;
  return {
    destinationReached: hops.some((hop) => hop.reached),
    hopsObserved: hops.length,
    responsiveHops: hops.filter((hop) => hop.probesAnswered > 0).length,
    probesSent: totalProbes,
    probesAnswered: answered,
    responseRatePercent: totalProbes ? Number((answered / totalProbes * 100).toFixed(1)) : 0,
    meanRttMs: mean(samples),
    minRttMs: samples.length ? Math.min(...samples) : null,
    maxRttMs: samples.length ? Math.max(...samples) : null,
    meanAbsoluteRttVariationMs: mean(deltas),
    destination,
  };
}

async function tracerouteBinary() {
  for (const path of BINARIES) {
    try { await access(path, fsConstants.X_OK); return path; } catch {}
  }
  return null;
}

/** Low-volume diagnostic route trace. Call only after exact-host ownership verification. */
export async function traceVerifiedHost(hostname) {
  let addresses;
  try { addresses = await resolvePublic(hostname); }
  catch (error) {
    return { status: 'blocked', destination: null, hops: [], metrics: null, notice: 'Network path was not traced because the target could not be safely resolved: ' + error.message };
  }
  const destination = addresses[0]?.address;
  if (!destination || !isPublicIp(destination)) {
    return { status: 'blocked', destination: null, hops: [], metrics: null, notice: 'Network path was not traced because no public destination address was available.' };
  }
  const binary = await tracerouteBinary();
  if (!binary) return { status: 'unavailable', destination, hops: [], metrics: null, notice: 'Traceroute is not installed on this FlawRadar worker; install the system traceroute utility to enable path diagnostics.' };

  return new Promise((resolve) => {
    let output = '';
    let settled = false;
    let timedOut = false;
    let timer = null;
    const finish = (result) => { if (!settled) { settled = true; if (timer) clearTimeout(timer); resolve(result); } };
    let child;
    try {
      child = spawn(binary, ['-n', '-m', String(MAX_HOPS), '-q', String(PROBES_PER_HOP), '-w', '1', '-N', '1', destination], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    } catch {
      finish({ status: 'unavailable', destination, hops: [], metrics: null, notice: 'Traceroute could not be started on this worker.' });
      return;
    }
    const collect = (chunk) => {
      output += chunk.toString('utf8');
      if (output.length > MAX_OUTPUT) child.kill('SIGKILL');
    };
    child.stdout.on('data', collect);
    child.stderr.on('data', collect);
    child.on('error', () => finish({ status: 'unavailable', destination, hops: [], metrics: null, notice: 'Traceroute could not be executed on this worker.' }));
    timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, TIMEOUT_MS);
    child.on('close', () => {
      const hops = parseTracerouteOutput(output, destination);
      if (!hops.length) {
        finish({ status: timedOut ? 'timeout' : 'unavailable', destination, hops: [], metrics: null, notice: timedOut ? 'Traceroute reached its time limit without usable hop data.' : 'The worker returned no usable traceroute hops; network policy or ICMP filtering may block path discovery.' });
        return;
      }
      finish({
        status: timedOut ? 'partial' : 'complete', destination, method: 'UDP traceroute', maxHops: MAX_HOPS,
        probesPerHop: PROBES_PER_HOP, hops, metrics: summarizeRoute(hops, destination),
        notice: timedOut ? 'Traceroute stopped at its time limit; the route is partial.' : null,
      });
    });
  });
}
