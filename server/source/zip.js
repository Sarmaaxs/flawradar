import zlib from 'node:zlib';
import { AppError } from '../errors.js';
import { normalizePath, skipReason } from './paths.js';

const EOCD = 0x06054b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;

const bad = (message) => new AppError(400, 'bad_zip', message);

/**
 * Read a .zip held in memory. Nothing is extracted to disk, so there is no path
 * to escape; names are still cleaned so they display safely.
 *
 * Limits protect against zip bombs: each file is inflated with a hard output
 * cap, and the sum of everything read is capped too.
 */
export function readZip(buffer, { maxEntries, maxFileBytes, maxTotalBytes }) {
  if (buffer.length < 22) throw bad('That file is not a zip archive.');

  let eocd = -1;
  for (let i = buffer.length - 22; i >= Math.max(0, buffer.length - 22 - 65_535); i -= 1) {
    if (buffer.readUInt32LE(i) === EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw bad('That file is not a zip archive.');

  const total = buffer.readUInt16LE(eocd + 10);
  const dirSize = buffer.readUInt32LE(eocd + 12);
  const dirOffset = buffer.readUInt32LE(eocd + 16);
  if (total === 0xffff || dirSize === 0xffffffff || dirOffset === 0xffffffff) {
    throw bad('ZIP64 archives are not supported. Zip the folder again without ZIP64, or drop the folder itself.');
  }
  if (total > maxEntries) throw bad(`The zip has ${total} entries. The limit is ${maxEntries}. Zip just the source folders.`);
  if (dirOffset + dirSize > buffer.length) throw bad('The zip archive is damaged.');

  const files = [];
  const skipped = [];
  const notices = [];
  let read = 0;
  let pos = dirOffset;

  for (let n = 0; n < total; n += 1) {
    if (pos + 46 > buffer.length || buffer.readUInt32LE(pos) !== CENTRAL) throw bad('The zip archive is damaged.');
    const flags = buffer.readUInt16LE(pos + 8);
    const method = buffer.readUInt16LE(pos + 10);
    const compressed = buffer.readUInt32LE(pos + 20);
    const size = buffer.readUInt32LE(pos + 24);
    const nameLen = buffer.readUInt16LE(pos + 28);
    const extraLen = buffer.readUInt16LE(pos + 30);
    const commentLen = buffer.readUInt16LE(pos + 32);
    const localOffset = buffer.readUInt32LE(pos + 42);
    const rawName = buffer.toString('utf8', pos + 46, pos + 46 + nameLen);
    pos += 46 + nameLen + extraLen + commentLen;

    if (rawName.endsWith('/')) continue; // folder entry
    const path = normalizePath(rawName);
    if (!path) {
      skipped.push({ path: rawName.slice(0, 80), reason: 'path' });
      continue;
    }
    const reason = skipReason(path);
    // Keep dependency manifests so CVE lookup can read them; everything else that
    // skipReason flags is dropped without inflating.
    const keepForCve = /(?:^|\/)(?:package-lock\.json|package\.json|requirements[\w.-]*\.txt)$/i.test(path);
    if (reason && !keepForCve) {
      skipped.push({ path, reason });
      continue;
    }
    if (reason && keepForCve) {
      skipped.push({ path, reason }); // still recorded as skipped for line rules
    }
    if (flags & 1) {
      skipped.push({ path, reason: 'encrypted' });
      continue;
    }
    if (size > maxFileBytes) {
      skipped.push({ path, reason: 'large' });
      continue;
    }
    if (read + size > maxTotalBytes) {
      notices.push(`Stopped reading the zip after ${Math.round(maxTotalBytes / 1_048_576)} MB of source. Zip fewer folders to scan the rest.`);
      skipped.push({ path, reason: 'total-limit' });
      break;
    }
    if (localOffset + 30 > buffer.length || buffer.readUInt32LE(localOffset) !== LOCAL) throw bad('The zip archive is damaged.');
    const start = localOffset + 30 + buffer.readUInt16LE(localOffset + 26) + buffer.readUInt16LE(localOffset + 28);
    if (start + compressed > buffer.length) throw bad('The zip archive is damaged.');
    const data = buffer.subarray(start, start + compressed);

    let bytes;
    try {
      if (method === 0) bytes = data;
      else if (method === 8) bytes = zlib.inflateRawSync(data, { maxOutputLength: maxFileBytes + 1 });
      else {
        skipped.push({ path, reason: 'compression' });
        continue;
      }
    } catch (err) {
      // Hitting the output cap means the entry inflates far past what its header claimed.
      skipped.push({ path, reason: err.code === 'ERR_BUFFER_TOO_LARGE' ? 'large' : 'bad-data' });
      continue;
    }
    if (bytes.length > maxFileBytes) {
      skipped.push({ path, reason: 'large' });
      continue;
    }
    read += bytes.length;
    files.push({ path, content: bytes.toString('utf8') });
  }

  return { files, skipped, notices };
}