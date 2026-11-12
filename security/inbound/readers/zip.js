// ============================================================
// OTLC Guardian - inbound-file check: zip reader
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// Reads a zip's central directory (zip64 included) and, on demand,
// one entry's bytes, in memory. Follows PKWARE APPNOTE 6.3.10. The
// central directory is the list an extractor uses, so it is the list
// judged; a local header whose name disagrees with it is reported.
//
// Names are decoded as extractors decode them: UTF-8 when flag bit
// 11 is set, otherwise code page 437, with an Info-ZIP Unicode Path
// field (0x7075) taking precedence when its CRC matches the raw name.
// ============================================================

import zlib from "zlib";
import { FormatError } from "../errors.js";
import { inflateLimited } from "../limits.js";

const SIG_EOCD    = 0x06054b50;
const SIG_EOCD64  = 0x06064b50;
const SIG_LOC64   = 0x07064b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL   = 0x04034b50;
const MAX_COMMENT = 0xFFFF;

const CP437_HIGH =
  "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀" +
  "αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ";

function cp437(bytes) {
  let out = "";
  for (const b of bytes) out += b < 0x80 ? String.fromCharCode(b) : CP437_HIGH[b - 0x80];
  return out;
}

const crc32 = typeof zlib.crc32 === "function" ? zlib.crc32 : null;

/**
 * @typedef {object} ZipEntry
 * @property {string} name decoded name from the central directory
 * @property {number} flags general purpose bit flags
 * @property {number} method compression method
 * @property {number} compressedSize
 * @property {number} size declared uncompressed size
 * @property {number} crc
 * @property {number} localOffset
 * @property {boolean} isDir
 * @property {boolean} isSymlink
 * @property {boolean} encrypted traditional (bit 0) or strong (bit 6) encryption
 * @property {number} [aesMethod] the real method behind WinZip AES (method 99)
 */

/**
 * Reads the central directory.
 * @param {Buffer} buf
 * @returns {{ entries: ZipEntry[] }}
 * @throws {FormatError}
 */
export function readZip(buf) {
  const eocd = findEocd(buf);
  let count = buf.readUInt16LE(eocd + 10);
  let cdSize = buf.readUInt32LE(eocd + 12);
  let cdOffset = buf.readUInt32LE(eocd + 16);

  if (count === 0xFFFF || cdSize === 0xFFFFFFFF || cdOffset === 0xFFFFFFFF) {
    const loc = eocd - 20;
    if (loc < 0 || buf.readUInt32LE(loc) !== SIG_LOC64) throw new FormatError("zip64 end record locator missing");
    const eocd64 = Number(buf.readBigUInt64LE(loc + 8));
    if (eocd64 + 56 > buf.length || buf.readUInt32LE(eocd64) !== SIG_EOCD64) throw new FormatError("zip64 end record missing");
    count = Number(buf.readBigUInt64LE(eocd64 + 32));
    cdSize = Number(buf.readBigUInt64LE(eocd64 + 40));
    cdOffset = Number(buf.readBigUInt64LE(eocd64 + 48));
  }
  if (cdOffset + cdSize > buf.length) throw new FormatError("central directory runs past the end of the file");

  const entries = [];
  let p = cdOffset;
  for (let i = 0; i < count; i++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== SIG_CENTRAL) throw new FormatError(`central directory entry ${i} is damaged`);
    const madeBy = buf.readUInt16LE(p + 4);
    const flags = buf.readUInt16LE(p + 8);
    let method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    let compressedSize = buf.readUInt32LE(p + 20);
    let size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const externalAttr = buf.readUInt32LE(p + 38);
    let localOffset = buf.readUInt32LE(p + 42);
    const end = p + 46 + nameLen + extraLen + commentLen;
    if (end > buf.length) throw new FormatError(`central directory entry ${i} runs past the end of the file`);
    const rawName = buf.subarray(p + 46, p + 46 + nameLen);
    const extra = buf.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen);

    let name = flags & 0x0800 ? rawName.toString("utf8") : cp437(rawName);
    let aesMethod;
    for (const field of extraFields(extra)) {
      if (field.id === 0x0001) {
        // Zip64: only the fields whose 32-bit value is saturated are present, in order.
        let q = 0;
        const next = () => { const v = Number(field.data.readBigUInt64LE(q)); q += 8; return v; };
        if (size === 0xFFFFFFFF && q + 8 <= field.data.length) size = next();
        if (compressedSize === 0xFFFFFFFF && q + 8 <= field.data.length) compressedSize = next();
        if (localOffset === 0xFFFFFFFF && q + 8 <= field.data.length) localOffset = next();
      } else if (field.id === 0x9901 && field.data.length >= 7) {
        aesMethod = field.data.readUInt16LE(5);
      } else if (field.id === 0x7075 && field.data.length >= 5 && crc32 && field.data[0] === 1) {
        if (field.data.readUInt32LE(1) === crc32(rawName)) name = field.data.subarray(5).toString("utf8");
      }
    }

    const unixMode = madeBy >> 8 === 3 ? externalAttr >>> 16 : 0;
    entries.push({
      name,
      flags,
      method,
      compressedSize,
      size,
      crc,
      localOffset,
      isDir: name.endsWith("/") || name.endsWith("\\"),
      isSymlink: (unixMode & 0xF000) === 0xA000,
      encrypted: Boolean(flags & 0x0001) || Boolean(flags & 0x0040) || method === 99,
      aesMethod,
    });
    p = end;
  }
  return { entries };
}

function findEocd(buf) {
  const stop = Math.max(0, buf.length - 22 - MAX_COMMENT);
  for (let i = buf.length - 22; i >= stop; i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) return i;
  }
  throw new FormatError("no zip end record (truncated or not a zip)");
}

function* extraFields(extra) {
  let q = 0;
  while (q + 4 <= extra.length) {
    const id = extra.readUInt16LE(q);
    const len = extra.readUInt16LE(q + 2);
    if (q + 4 + len > extra.length) return;
    yield { id, data: extra.subarray(q + 4, q + 4 + len) };
    q += 4 + len;
  }
}

/**
 * Reads one entry's bytes. Stored and deflated entries only; the
 * caller holds anything else. Every byte inflated counts against the
 * budget.
 *
 * @param {Buffer} buf
 * @param {ZipEntry} entry
 * @param {import("../limits.js").Budget} budget
 * @returns {{ data: Buffer, localName: string, crcOk: boolean }}
 * @throws {FormatError}
 */
export function readZipEntry(buf, entry, budget) {
  const p = entry.localOffset;
  if (p + 30 > buf.length || buf.readUInt32LE(p) !== SIG_LOCAL) throw new FormatError(`local header of ${entry.name} is missing`);
  const nameLen = buf.readUInt16LE(p + 26);
  const extraLen = buf.readUInt16LE(p + 28);
  const rawLocal = buf.subarray(p + 30, p + 30 + nameLen);
  const localName = buf.readUInt16LE(p + 6) & 0x0800 ? rawLocal.toString("utf8") : cp437(rawLocal);
  const start = p + 30 + nameLen + extraLen;
  if (start + entry.compressedSize > buf.length) throw new FormatError(`${entry.name} runs past the end of the file`);
  const stored = buf.subarray(start, start + entry.compressedSize);

  let data;
  if (entry.method === 0) {
    // A view of bytes already in memory: nothing is decompressed.
    data = stored;
  } else if (entry.method === 8) {
    try {
      data = inflateLimited("raw", stored, budget);
    } catch (error) {
      if (error?.name === "LimitError") throw error;
      throw new FormatError(`${entry.name} does not inflate: ${error.message}`);
    }
  } else {
    throw new FormatError(`${entry.name} uses compression method ${entry.method}`);
  }
  const crcOk = crc32 ? crc32(data) === entry.crc : true;
  return { data, localName, crcOk };
}
