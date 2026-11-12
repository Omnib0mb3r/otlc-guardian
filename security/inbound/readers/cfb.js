// ============================================================
// OTLC Guardian - inbound-file check: compound file reader
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// Reads a Compound File Binary ([MS-CFB]: legacy .doc, .xls, .ppt,
// .msi, .msg, OLE objects) in memory: header, FAT and DIFAT, the
// directory tree, the mini stream. Every sector chain is bounded and
// checked for loops, so a hostile file cannot make the reader spin.
// ============================================================

import { FormatError } from "../errors.js";

const FREESECT   = 0xFFFFFFFF;
const ENDOFCHAIN = 0xFFFFFFFE;
const MAX_REGSECT = 0xFFFFFFFA;
const NOSTREAM   = 0xFFFFFFFF;
const TYPE = { 1: "storage", 2: "stream", 5: "root" };

/**
 * @typedef {object} CfbEntry
 * @property {string} path  storage names joined with "/"
 * @property {string} name
 * @property {"storage"|"stream"|"root"} type
 * @property {number} size
 * @property {string} clsid lower-case GUID text, "" when zero
 */

/**
 * @param {Buffer} buf
 * @param {import("../limits.js").Budget} budget
 * @returns {{ entries: CfbEntry[], root: CfbEntry, read: (entry: CfbEntry) => Buffer }}
 * @throws {FormatError}
 */
export function readCfb(buf, budget) {
  if (buf.length < 512) throw new FormatError("compound file header is cut short");
  const major = buf.readUInt16LE(26);
  const sectorShift = buf.readUInt16LE(30);
  const miniShift = buf.readUInt16LE(32);
  if (!((major === 3 && sectorShift === 9) || (major === 4 && sectorShift === 12)) || miniShift !== 6) {
    throw new FormatError(`compound file version ${major} with sector shift ${sectorShift} is not valid`);
  }
  const sectorSize = 1 << sectorShift;
  const sectorCount = Math.floor((buf.length - sectorSize) / sectorSize) + (buf.length % sectorSize ? 1 : 0);
  const offsetOf = (sid) => (sid + 1) * sectorSize;
  const sector = (sid) => {
    if (sid >= sectorCount) throw new FormatError(`sector ${sid} is past the end of the file`);
    return buf.subarray(offsetOf(sid), Math.min(buf.length, offsetOf(sid) + sectorSize));
  };

  // DIFAT: the first 109 FAT sector ids sit in the header, the rest in a chain.
  const fatSectors = [];
  for (let i = 0; i < 109; i++) {
    const sid = buf.readUInt32LE(76 + i * 4);
    if (sid <= MAX_REGSECT) fatSectors.push(sid);
  }
  let difat = buf.readUInt32LE(68);
  const seenDifat = new Set();
  while (difat <= MAX_REGSECT) {
    if (seenDifat.has(difat) || seenDifat.size > sectorCount) throw new FormatError("DIFAT chain loops");
    seenDifat.add(difat);
    const s = sector(difat);
    const per = sectorSize / 4 - 1;
    for (let i = 0; i < per; i++) {
      const sid = s.readUInt32LE(i * 4);
      if (sid <= MAX_REGSECT) fatSectors.push(sid);
    }
    difat = s.readUInt32LE(per * 4);
  }
  const fat = [];
  for (const sid of fatSectors) {
    const s = sector(sid);
    for (let i = 0; i + 4 <= s.length; i += 4) fat.push(s.readUInt32LE(i));
  }

  const chain = (start, table, limit) => {
    const out = [];
    const seen = new Set();
    let sid = start;
    while (sid !== ENDOFCHAIN && sid !== FREESECT) {
      if (sid > MAX_REGSECT || sid >= table.length) throw new FormatError(`sector chain points at ${sid}, outside the table`);
      if (seen.has(sid) || out.length > limit) throw new FormatError("sector chain loops");
      seen.add(sid);
      out.push(sid);
      sid = table[sid];
    }
    return out;
  };
  const readChain = (start, size) => {
    budget.tick();
    const sids = chain(start, fat, sectorCount);
    const out = Buffer.concat(sids.map(sector));
    return size === undefined ? out : out.subarray(0, Math.min(size, out.length));
  };

  // Directory: 128-byte entries along the directory chain.
  const dirBytes = readChain(buf.readUInt32LE(48));
  const raw = [];
  for (let p = 0; p + 128 <= dirBytes.length; p += 128) {
    const nameLen = dirBytes.readUInt16LE(p + 64);
    const type = dirBytes[p + 66];
    raw.push({
      name: nameLen >= 2 ? dirBytes.subarray(p, p + Math.min(64, nameLen) - 2).toString("utf16le") : "",
      type: TYPE[type],
      left: dirBytes.readUInt32LE(p + 68),
      right: dirBytes.readUInt32LE(p + 72),
      child: dirBytes.readUInt32LE(p + 76),
      clsid: guid(dirBytes.subarray(p + 80, p + 96)),
      start: dirBytes.readUInt32LE(p + 116),
      size: major === 3 ? dirBytes.readUInt32LE(p + 120) : Number(dirBytes.readBigUInt64LE(p + 120)),
    });
  }
  if (raw.length === 0 || raw[0].type !== "root") throw new FormatError("compound file has no root entry");

  const cutoff = buf.readUInt32LE(56);
  const rootEntry = raw[0];
  let miniStream = null;
  let miniFat = null;
  const mini = () => {
    if (miniStream) return;
    miniStream = readChain(rootEntry.start, rootEntry.size);
    const mf = readChain(buf.readUInt32LE(60));
    miniFat = [];
    for (let i = 0; i + 4 <= mf.length; i += 4) miniFat.push(mf.readUInt32LE(i));
  };

  // Walk the red-black tree of each storage; a loop or a bad index is malformed.
  const entries = [];
  const visited = new Set();
  const walk = (index, prefix) => {
    const stack = [index];
    while (stack.length) {
      const i = stack.pop();
      if (i === NOSTREAM) continue;
      if (i >= raw.length || visited.has(i)) throw new FormatError("compound file directory tree is damaged");
      visited.add(i);
      const e = raw[i];
      stack.push(e.left, e.right);
      if (!e.type) continue;
      const entry = { path: prefix ? `${prefix}/${e.name}` : e.name, name: e.name, type: e.type, size: e.size, clsid: e.clsid, start: e.start };
      entries.push(entry);
      if (e.type === "storage") walk(e.child, entry.path);
    }
  };
  visited.add(0);
  const root = { path: "", name: rootEntry.name, type: "root", size: rootEntry.size, clsid: rootEntry.clsid, start: rootEntry.start };
  walk(rootEntry.child, "");

  const read = (entry) => {
    if (entry.type !== "stream") return Buffer.alloc(0);
    if (entry.size < cutoff) {
      mini();
      const sids = chain(entry.start, miniFat, miniFat.length);
      const parts = sids.map((sid) => {
        if ((sid + 1) * 64 > miniStream.length) throw new FormatError(`mini sector ${sid} is past the mini stream`);
        return miniStream.subarray(sid * 64, sid * 64 + 64);
      });
      return Buffer.concat(parts).subarray(0, entry.size);
    }
    return readChain(entry.start, entry.size);
  };
  return { entries, root, read };
}

function guid(b) {
  if (b.every((x) => x === 0)) return "";
  const hex = (s, e, le) => {
    const part = [...b.subarray(s, e)];
    return (le ? part.reverse() : part).map((x) => x.toString(16).padStart(2, "0")).join("");
  };
  return `${hex(0, 4, true)}-${hex(4, 6, true)}-${hex(6, 8, true)}-${hex(8, 10)}-${hex(10, 16)}`;
}
