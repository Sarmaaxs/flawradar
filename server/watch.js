import crypto from 'node:crypto';
import { config } from './config.js';
import { AppError } from './errors.js';
import * as db from './db.js';
import { sendMail } from './mail.js';
import { parseTarget, resolvePublic } from './scanner/net.js';
import { startScan } from './scans.js';
import { checkOwnership } from './verify.js';

// A watch is a scheduled rescan of a host whose owner proved control, with an email to the
// address that signed up when the grade drops. No accounts, no passwords: the address is
// confirmed by a link, and every email carries a link that stops the watch.

const GRADES = ['A', 'B', 'C', 'D', 'F'];
export const gradeWorse = (now, before) => GRADES.indexOf(now) > GRADES.indexOf(before);
const link = (path, w) => `${config.baseUrl}${path}?id=${w.id}&s=${w.secret}`;

const same = (a, b) => {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

export function normalizeEmail(value) {
  const e = String(value || '').trim().toLowerCase();
  if (e.length > 254 || !/^[^\s<>@,;"]+@[^\s<>@,;"]+\.[^\s<>@,;"]+$/.test(e)) {
    throw new AppError(400, 'bad_email', 'That does not look like an email address.');
  }
  return e;
}

export async function subscribe({ url, email, send = sendMail }) {
  if (!config.mail.enabled) {
    throw new AppError(503, 'watch_unavailable', 'Watches are not available right now. Please try again later.');
  }
  const address = normalizeEmail(email);
  const target = parseTarget(url);
  await resolvePublic(target.host);
  const proof = await checkOwnership(target);
  if (!proof.verified) {
    throw new AppError(403, 'needs_verification', 'Watches need proof that you control this host, so nobody can have a site they do not own scanned every day.', {
      host: target.host,
      tried: proof.tried,
    });
  }

  let watch = db.getWatchFor(target.host, address);
  if (watch?.confirmed) return { host: target.host }; // nothing new to confirm; the response never says whether it existed
  if (!watch) {
    if (db.countWatchesFor(address) >= config.maxWatchesPerEmail) {
      throw new AppError(429, 'too_many_watches', `One address can watch at most ${config.maxWatchesPerEmail} sites.`);
    }
    db.insertWatch({ id: crypto.randomBytes(12).toString('hex'), host: target.host, url: target.input, email: address, secret: crypto.randomBytes(16).toString('hex') });
    watch = db.getWatchFor(target.host, address);
  }
  await send({
    to: address,
    subject: `Confirm: FlawRadar watch for ${target.host}`,
    text: [
      `Someone asked FlawRadar to scan ${target.host} every ${config.watchIntervalHours} hours and email this address when its grade gets worse.`,
      '',
      'If that was you, confirm here:',
      link('/watch/confirm', watch),
      '',
      'If it was not, ignore this message. Nothing happens unless the link is opened, and the request is forgotten after two days.',
    ].join('\n'),
  });
  return { host: target.host };
}

function find(id, secret) {
  const w = db.getWatch(String(id || ''));
  if (!w || !same(w.secret, secret || '')) throw new AppError(404, 'not_found', 'That link is not valid. It may have been used already.');
  return w;
}

export function confirm(id, secret) {
  const w = find(id, secret);
  db.confirmWatch(w.id);
  return { host: w.host, intervalHours: config.watchIntervalHours };
}

export function stop(id, secret) {
  const w = find(id, secret);
  db.deleteWatch(w.id);
  return { host: w.host };
}

// ---------------------------------------------------------------- the scheduler

async function notify(w, subject, lines, send) {
  await send({
    to: w.email,
    subject,
    text: [...lines, '', `Stop watching ${w.host}: ${link('/watch/stop', w)}`].join('\n'),
  });
}

/** Runs after a watch's scan finishes. Decides whether to send an alert. */
export async function afterScan(w, scanId, send = sendMail) {
  const row = db.getScan(scanId);
  if (!row || row.status !== 'done') {
    db.watchTouched(w.id); // blocked or failed: try again next round, do not alert
    return 'no-result';
  }
  const before = { score: w.last_score, grade: w.last_grade };
  db.watchRan(w.id, { scanId, score: row.score, grade: row.grade });
  if (!before.grade) return 'baseline';
  const dropped = gradeWorse(row.grade, before.grade) || (before.score != null && row.score <= before.score - 10);
  if (!dropped) return 'ok';
  await notify(w, `${w.host}: grade ${before.grade} to ${row.grade}`, [
    `FlawRadar scanned ${w.host} and the result is worse than last time.`,
    '',
    `Before: ${before.score} (${before.grade})`,
    `Now:    ${row.score} (${row.grade})`,
    '',
    `Full report: ${config.baseUrl}/report/${scanId}`,
    `Reports are deleted after ${config.retentionDays} days.`,
  ], send);
  db.watchAlerted(w.id);
  return 'alerted';
}

/** One pass: start scans for watches that are due. Returns how many were started. */
export async function runDue({ now = Date.now(), send = sendMail, start = startScan, limit = 3 } = {}) {
  if (!config.mail.enabled) return 0;
  db.purgeStaleWatches();
  let started = 0;
  for (const w of db.dueWatches(now - config.watchIntervalHours * 3_600_000, limit)) {
    let target;
    try {
      target = parseTarget(w.url || w.host);
      await resolvePublic(target.host);
    } catch {
      db.pauseWatch(w.id, 'host not scannable');
      continue;
    }
    let proof;
    try {
      proof = await checkOwnership(target);
    } catch {
      db.watchTouched(w.id);
      continue;
    }
    if (!proof.verified) {
      // The owner removed the proof. That withdraws permission, so scans stop and the sign-up is told.
      db.pauseWatch(w.id, 'proof removed');
      await notify(w, `FlawRadar watch for ${w.host} paused`, [
        `The ownership proof for ${w.host} is no longer in place, so FlawRadar has stopped scanning it.`,
        'Put the proof back and sign up again if you want the watch to continue.',
      ], send).catch(() => {});
      continue;
    }
    try {
      start(target, { termsVersion: 'watch', onDone: (scanId) => afterScan(w, scanId, send) });
      db.watchTouched(w.id);
      started += 1;
    } catch (err) {
      if (!(err instanceof AppError)) throw err; // busy: leave it due, try next round
    }
  }
  return started;
}

export function startWatcher(everyMs = 5 * 60_000) {
  const timer = setInterval(() => runDue().catch((err) => console.error('watch run failed', err)), everyMs);
  timer.unref();
  return timer;
}
