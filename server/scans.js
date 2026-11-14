import crypto from 'node:crypto';
import { config } from './config.js';
import { AppError } from './errors.js';
import * as db from './db.js';
import { runScan } from './scanner/scan.js';

let running = 0;
const queue = [];

export function queueLength() {
  return queue.length;
}

export function startScan(target, { deep = false, termsVersion = null, allow = null } = {}) {
  if (queue.length >= config.maxQueuedScans) {
    throw new AppError(503, 'busy', 'Wsec is busy. Try again in a minute.');
  }
  const id = crypto.randomBytes(12).toString('hex');
  db.insertScan({ id, host: target.host, url: target.input, deep, createdAt: Date.now(), termsVersion });
  queue.push({ id, target, deep, allow });
  pump();
  return id;
}

function pump() {
  while (running < config.maxConcurrentScans && queue.length) {
    const job = queue.shift();
    running += 1;
    execute(job).finally(() => {
      running -= 1;
      pump();
    });
  }
}

async function execute({ id, target, deep, allow }) {
  const steps = [];
  const onStep = (name, state) => {
    const existing = steps.find((s) => s.name === name);
    if (existing) existing.state = state;
    else steps.push({ name, state });
    db.setProgress(id, steps);
  };
  db.setStatus(id, 'running');

  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(new AppError(504, 'timeout', 'The scan took too long and was stopped.')),
      config.scanTimeoutMs,
    );
  });

  try {
    const result = await Promise.race([runScan(target, { deep, onStep }), timeout]);
    if (allow) result.allow = allow;
    db.finishScan(id, {
      status: result.blocked ? 'blocked' : 'done',
      score: result.score,
      grade: result.grade,
      result,
    });
  } catch (err) {
    if (!(err instanceof AppError)) console.error(`scan ${id} crashed`, err);
    db.failScan(id, err instanceof AppError ? err.message : 'The scan failed unexpectedly.');
  } finally {
    clearTimeout(timer);
  }
}