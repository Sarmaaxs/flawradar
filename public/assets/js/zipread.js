import { MANIFEST_FOR_CVE, normalizePath, skipReason } from '/assets/engine/paths.js';

// Reads a .zip inside the browser. Nothing is uploaded and nothing is extracted to disk.
// Same limits as the server reader: every entry is inflated with a hard output cap, and the
// sum of everything read is capped too, so a zip bomb stops early.

const EOCD = 0x06054b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;

export class ZipError extends Error {}
const bad = (m) => new ZipError(m);

async function inflate(bytes, cap) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  const reader = stream.getReader();
  const parts = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > cap) {
      await reader.cancel();
      return null; // inflates past the cap
    }
    parts.push(value);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export async function readZip(file, { maxEntries, maxFileBytes, maxTotalBytes }) {
  const buffer = new Uint8Array(await file.arrayBuffer());
  const view = new DataView(buffer.buffer);
  if (buffer.length < 22) throw bad('That file is not a zip archive.');

  let eocd = -1;
  for (let i = buffer.length - 22; i >= Math.max(0, buffer.length - 22 - 65535); i -= 1) {
    if (view.getUint32(i, true) === EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw bad('That file is not a zip archive.');

  const total = view.getUint16(eocd + 10, true);
  const dirSize = view.getUint32(eocd + 12, true);
  const dirOffset = view.getUint32(eocd + 16, true);
  if (total === 0xffff || dirSize === 0xffffffff || dirOffset === 0xffffffff) {
    throw bad('ZIP64 archives are not supported. Zip the folder again without ZIP64, or drop the folder itself.');
  }
  if (total > maxEntries) throw bad(`The zip has ${total} entries. The limit is ${maxEntries}. Zip just the source folders.`);
  if (dirOffset + dirSize > buffer.length) throw bad('The zip archive is damaged.');

  const decoder = new TextDecoder('utf-8');
  const files = [];
  const skipped = [];
  const notices = [];
  let read = 0;
  let pos = dirOffset;

  for (let n = 0; n < total; n += 1) {
    if (pos + 46 > buffer.length || view.getUint32(pos, true) !== CENTRAL) throw bad('The zip archive is damaged.');
    const flags = view.getUint16(pos + 8, true);
    const method = view.getUint16(pos + 10, true);
    const compressed = view.getUint32(pos + 20, true);
    const size = view.getUint32(pos + 24, true);
    const nameLen = view.getUint16(pos + 28, true);
    const extraLen = view.getUint16(pos + 30, true);
    const commentLen = view.getUint16(pos + 32, true);
    const localOffset = view.getUint32(pos + 42, true);
    const rawName = decoder.decode(buffer.subarray(pos + 46, pos + 46 + nameLen));
    pos += 46 + nameLen + extraLen + commentLen;

    if (rawName.endsWith('/')) continue;
    const path = normalizePath(rawName);
    if (!path) { skipped.push({ path: rawName.slice(0, 80), reason: 'path' }); continue; }
    let reason = skipReason(path);
    const manifest = Boolean(reason) && MANIFEST_FOR_CVE.test(path);
    if (reason && !manifest) { skipped.push({ path, reason }); continue; }
    if (flags & 1) { skipped.push({ path, reason: 'encrypted' }); continue; }
    if (size > maxFileBytes) { skipped.push({ path, reason: 'large' }); continue; }
    if (read + size > maxTotalBytes) {
      notices.push(`Stopped reading the zip after ${Math.round(maxTotalBytes / 1_048_576)} MB of source. Zip fewer folders to scan the rest.`);
      skipped.push({ path, reason: 'total-limit' });
      break;
    }
    if (localOffset + 30 > buffer.length || view.getUint32(localOffset, true) !== LOCAL) throw bad('The zip archive is damaged.');
    const start = localOffset + 30 + view.getUint16(localOffset + 26, true) + view.getUint16(localOffset + 28, true);
    if (start + compressed > buffer.length) throw bad('The zip archive is damaged.');
    const data = buffer.subarray(start, start + compressed);

    let bytes;
    if (method === 0) bytes = data;
    else if (method === 8) {
      try {
        bytes = await inflate(data, maxFileBytes);
      } catch {
        skipped.push({ path, reason: 'bad-data' });
        continue;
      }
      if (!bytes) { skipped.push({ path, reason: 'large' }); continue; }
    } else { skipped.push({ path, reason: 'compression' }); continue; }
    if (bytes.length > maxFileBytes) { skipped.push({ path, reason: 'large' }); continue; }
    read += bytes.length;
    if (manifest) {
      // Kept only for the vulnerability lookup; the line rules skip it.
      skipped.push({ path, reason, content: decoder.decode(bytes) });
      continue;
    }
    files.push({ path, content: decoder.decode(bytes) });
  }
  return { files, skipped, notices };
}