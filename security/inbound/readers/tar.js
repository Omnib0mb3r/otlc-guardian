// ============================================================
// OTLC Guardian - inbound-file check: tar and gzip readers
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// tar: POSIX ustar and pax headers, GNU long names, in memory. Each
// header's checksum is verified; a header that fails it ends the
// archive as damaged rather than being guessed at.
// gzip: the member name from the header; the data is inflated by
// limits.js under the budget.
// ============================================================

import { FormatError } from "../errors.js";

const BLOCK = 512;

/**
 * @typedef {object} TarEntry
 * @property {string} name
 * @property {"file"|"dir"|"symlink"|"hardlink"|"special"} kind
 * @property {string} [linkname]
 * @property {Buffer} data a view of the archive bytes (files only)
 */

/**
 * @param {Buffer} buf
 * @param {import("../limits.js").Budget} budget
 * @returns {TarEntry[]}
 * @throws {FormatError}
 */
export function readTar(buf, budget) {
  const entries = [];
  let p = 0;
  let longName;
  let longLink;
  let pax = {};
  while (p + BLOCK <= buf.length) {
    budget.tick();
    const header = buf.subarray(p, p + BLOCK);
    if (header.every((b) => b === 0)) break;
    if (!checksumOk(header)) {
      if (entries.length === 0 && p === 0) throw new FormatError("tar header checksum does not match");
      throw new FormatError(`tar header at byte ${p} is damaged`);
    }
    const size = readSize(header.subarray(124, 136));
    const typeflag = String.fromCharCode(header[156] || 0x30);
    const dataStart = p + BLOCK;
    if (dataStart + size > buf.length) throw new FormatError(`tar entry at byte ${p} runs past the end of the file`);
    const data = buf.subarray(dataStart, dataStart + size);
    p = dataStart + Math.ceil(size / BLOCK) * BLOCK;

    if (typeflag === "L") { longName = cString(data); continue; }
    if (typeflag === "K") { longLink = cString(data); continue; }
    if (typeflag === "x") { pax = parsePax(data); continue; }
    if (typeflag === "g") continue;

    const ustar = header.subarray(257, 262).toString("latin1") === "ustar";
    const prefix = ustar ? cString(header.subarray(345, 500)) : "";
    let name = longName ?? pax.path ?? (prefix ? `${prefix}/${cString(header.subarray(0, 100))}` : cString(header.subarray(0, 100)));
    const linkname = longLink ?? pax.linkpath ?? cString(header.subarray(157, 257));
    longName = longLink = undefined;
    pax = {};

    let kind;
    if (typeflag === "0" || typeflag === "7" || typeflag === "\0") kind = name.endsWith("/") ? "dir" : "file";
    else if (typeflag === "5") kind = "dir";
    else if (typeflag === "2") kind = "symlink";
    else if (typeflag === "1") kind = "hardlink";
    else kind = "special";
    if (kind === "dir" && !name.endsWith("/")) name += "/";
    entries.push({ name, kind, linkname, data });
  }
  return entries;
}

function checksumOk(header) {
  const stored = parseInt(cString(header.subarray(148, 156)).trim(), 8);
  if (Number.isNaN(stored)) return false;
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : header[i];
  return sum === stored;
}

function readSize(field) {
  if (field[0] & 0x80) {
    // GNU base-256: big-endian binary after the marker bit.
    let n = 0;
    for (let i = 1; i < field.length; i++) n = n * 256 + field[i];
    return n;
  }
  const n = parseInt(cString(field).trim() || "0", 8);
  if (Number.isNaN(n)) throw new FormatError("tar size field is not a number");
  return n;
}

function cString(bytes) {
  const end = bytes.indexOf(0);
  return bytes.subarray(0, end < 0 ? bytes.length : end).toString("utf8");
}

/** pax records: "<length> <key>=<value>\n". */
function parsePax(data) {
  const out = {};
  let p = 0;
  while (p < data.length) {
    const space = data.indexOf(0x20, p);
    if (space < 0) break;
    const len = parseInt(data.subarray(p, space).toString("latin1"), 10);
    if (!(len > 0) || p + len > data.length) break;
    const record = data.subarray(space + 1, p + len - 1).toString("utf8");
    const eq = record.indexOf("=");
    if (eq > 0) out[record.slice(0, eq)] = record.slice(eq + 1);
    p += len;
  }
  return out;
}

/**
 * The member name stored in a gzip header (FNAME), if any.
 * @param {Buffer} buf
 * @returns {string|undefined}
 */
export function gzipName(buf) {
  if (buf.length < 10) return undefined;
  const flags = buf[3];
  let p = 10;
  if (flags & 0x04) {
    if (p + 2 > buf.length) return undefined;
    p += 2 + buf.readUInt16LE(p);
  }
  if (!(flags & 0x08)) return undefined;
  const end = buf.indexOf(0, p);
  if (end < 0) return undefined;
  return buf.subarray(p, end).toString("latin1");
}
