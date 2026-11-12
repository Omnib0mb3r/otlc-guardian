// ============================================================
// OTLC Guardian - inbound-file check: PDF reader
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// Finds every object in a PDF by scanning for "N G obj" rather than
// trusting the cross-reference table, so objects an incremental
// update or a damaged xref would hide are still read. Object streams
// are decoded and their objects added. Names are returned with their
// #xx escapes decoded (/J#61vaScript is /JavaScript), which is how a
// PDF reader sees them.
//
// Filters: FlateDecode (with PNG and TIFF predictors), LZWDecode,
// ASCII85Decode, ASCIIHexDecode, RunLengthDecode. Image filters
// (DCT, JPX, CCITTFax, JBIG2) are left encoded: they hold pictures,
// not objects or text. A stream with any other filter is reported
// unreadable.
// ============================================================

import { inflateLimited } from "../limits.js";
import { FormatError } from "../errors.js";

const IMAGE_FILTERS = new Set(["DCTDecode", "DCT", "JPXDecode", "CCITTFaxDecode", "CCF", "JBIG2Decode"]);

/**
 * @typedef {object} PdfObject
 * @property {number} num
 * @property {string} dict  the object's text outside any stream, names decoded
 * @property {Buffer} [raw] the stream's bytes as stored
 * @property {boolean} [inObjectStream]
 */

/** Decodes #xx escapes in every name token. */
export function decodeNames(text) {
  return text.replace(/\/[^\s/<>[\]()%{}]*/g, (name) =>
    name.includes("#") ? name.replace(/#([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))) : name);
}

/**
 * @param {Buffer} buf
 * @param {import("../limits.js").Budget} budget
 * @returns {{ objects: PdfObject[], trailers: string, encrypted: boolean, unreadable: string[], decode: (o: PdfObject) => Buffer|null }}
 */
export function readPdf(buf, budget) {
  const text = buf.toString("latin1");
  const objects = [];
  const unreadable = [];
  const header = /(\d+)\s+(\d+)\s+obj\b/g;
  let m;
  while ((m = header.exec(text))) {
    budget.tick();
    const start = m.index + m[0].length;
    const end = text.indexOf("endobj", start);
    const streamAt = streamKeyword(text, start, end < 0 ? text.length : end);
    if (streamAt < 0) {
      objects.push({ num: Number(m[1]), dict: decodeNames(text.slice(start, end < 0 ? text.length : end)) });
      if (end < 0) break;
      header.lastIndex = end;
      continue;
    }
    const dict = decodeNames(text.slice(start, streamAt.keyword));
    let dataStart = streamAt.data;
    const declared = /\/Length\s+(\d+)(?!\s+\d+\s+R)/.exec(dict);
    let dataEnd = -1;
    if (declared) {
      const candidate = dataStart + Number(declared[1]);
      if (/^\s*endstream/.test(text.slice(candidate, candidate + 20))) dataEnd = candidate;
    }
    if (dataEnd < 0) {
      const es = text.indexOf("endstream", dataStart);
      dataEnd = es < 0 ? text.length : es;
      // The EOL before "endstream" is not part of the data.
      if (text[dataEnd - 1] === "\n") dataEnd--;
      if (text[dataEnd - 1] === "\r") dataEnd--;
    }
    objects.push({ num: Number(m[1]), dict, raw: buf.subarray(dataStart, Math.max(dataStart, dataEnd)) });
    const after = text.indexOf("endobj", dataEnd);
    header.lastIndex = after < 0 ? text.length : after;
  }

  const trailers = decodeNames([...text.matchAll(/trailer\s*(<<[\s\S]*?>>)\s*startxref/g)].map((t) => t[1]).join("\n"));
  const encrypted = /\/Encrypt\b/.test(trailers) ||
    objects.some((o) => /\/Type\s*\/XRef\b/.test(o.dict) && /\/Encrypt\b/.test(o.dict));

  const decode = (o) => {
    if (!o.raw) return null;
    if (o.decoded !== undefined) return o.decoded;
    try {
      o.decoded = decodeStream(o.dict, o.raw, budget);
    } catch (error) {
      if (error?.name === "LimitError") throw error;
      if (!(error instanceof FormatError)) throw error;
      unreadable.push(`object ${o.num}: ${error.message}`);
      o.decoded = null;
    }
    return o.decoded;
  };

  // Objects packed in object streams are read like any other.
  if (!encrypted) {
    for (const o of [...objects]) {
      if (!/\/Type\s*\/ObjStm\b/.test(o.dict)) continue;
      const data = decode(o);
      if (!data) continue;
      const first = Number(/\/First\s+(\d+)/.exec(o.dict)?.[1] ?? NaN);
      const count = Number(/\/N\s+(\d+)/.exec(o.dict)?.[1] ?? NaN);
      const body = data.toString("latin1");
      if (!Number.isFinite(first) || !Number.isFinite(count)) {
        unreadable.push(`object stream ${o.num} has no /First or /N`);
        continue;
      }
      const ints = body.slice(0, first).trim().split(/\s+/).map(Number);
      for (let i = 0; i < count && 2 * i + 1 < ints.length; i++) {
        const from = first + ints[2 * i + 1];
        const to = i + 1 < count && 2 * i + 3 < ints.length ? first + ints[2 * i + 3] : body.length;
        objects.push({ num: ints[2 * i], dict: decodeNames(body.slice(from, to)), inObjectStream: true });
      }
    }
  }
  return { objects, trailers, encrypted, unreadable, decode };
}

/** Where the stream keyword after a dictionary sits, or -1. */
function streamKeyword(text, from, to) {
  const re = />>\s*stream(\r\n|\n|\r)/g;
  re.lastIndex = from;
  const m = re.exec(text);
  if (!m || m.index >= to) return -1;
  const keyword = m.index + 2;
  return { keyword, data: m.index + m[0].length };
}

/** The filters and their parameters, in order. */
export function filtersOf(dict) {
  const f = /\/Filter\s*(\[[^\]]*\]|\/[A-Za-z0-9]+)/.exec(dict);
  if (!f) return [];
  return [...f[1].matchAll(/\/([A-Za-z0-9]+)/g)].map((x) => x[1]);
}

const isImageDict = (dict) => /\/Subtype\s*\/Image\b/.test(dict);

/**
 * Decodes a stream through its filters. Returns null for an image
 * left encoded on purpose.
 * @throws {FormatError} for a filter Guardian has no decoder for, or data that does not decode
 */
export function decodeStream(dict, raw, budget) {
  let data = raw;
  const filters = filtersOf(dict);
  const parms = /\/DecodeParms\s*<<([\s\S]*?)>>/.exec(dict)?.[1] ?? "";
  for (const filter of filters) {
    budget.tick();
    if (IMAGE_FILTERS.has(filter)) return null;
    if (filter === "FlateDecode" || filter === "Fl") {
      try {
        data = inflateLimited("zlib", data, budget, { tolerant: true });
      } catch (error) {
        if (error?.name === "LimitError") throw error;
        throw new FormatError(`Flate data does not inflate (${error.message})`);
      }
      data = unpredict(data, parms);
    } else if (filter === "LZWDecode" || filter === "LZW") {
      data = unpredict(lzw(data, !/\/EarlyChange\s+0\b/.test(parms), budget), parms);
    } else if (filter === "ASCII85Decode" || filter === "A85") {
      data = ascii85(data);
    } else if (filter === "ASCIIHexDecode" || filter === "AHx") {
      data = asciiHex(data);
    } else if (filter === "RunLengthDecode" || filter === "RL") {
      data = runLength(data);
    } else if (filter === "Crypt") {
      throw new FormatError("stream is encrypted (Crypt filter)");
    } else {
      throw new FormatError(`stream uses the ${filter} filter, which Guardian cannot decode`);
    }
  }
  if (filters.length === 0 && isImageDict(dict)) return null;
  return data;
}

function unpredict(data, parms) {
  const predictor = Number(/\/Predictor\s+(\d+)/.exec(parms)?.[1] ?? 1);
  if (predictor < 2) return data;
  const colors = Number(/\/Colors\s+(\d+)/.exec(parms)?.[1] ?? 1);
  const bpc = Number(/\/BitsPerComponent\s+(\d+)/.exec(parms)?.[1] ?? 8);
  const columns = Number(/\/Columns\s+(\d+)/.exec(parms)?.[1] ?? 1);
  const bpp = Math.max(1, Math.ceil((colors * bpc) / 8));
  const rowLen = Math.ceil((columns * colors * bpc) / 8);
  if (predictor === 2) {
    if (bpc !== 8) throw new FormatError("TIFF predictor with other than 8 bits per component");
    const out = Buffer.from(data);
    for (let r = 0; r < out.length; r += rowLen) {
      for (let i = bpp; i < rowLen && r + i < out.length; i++) out[r + i] = (out[r + i] + out[r + i - bpp]) & 0xFF;
    }
    return out;
  }
  // PNG predictors: each row starts with its filter type.
  const rows = Math.floor(data.length / (rowLen + 1));
  const out = Buffer.alloc(rows * rowLen);
  const prev = Buffer.alloc(rowLen);
  for (let r = 0; r < rows; r++) {
    const type = data[r * (rowLen + 1)];
    const row = data.subarray(r * (rowLen + 1) + 1, (r + 1) * (rowLen + 1));
    const cur = out.subarray(r * rowLen, (r + 1) * rowLen);
    for (let i = 0; i < rowLen; i++) {
      const left = i >= bpp ? cur[i - bpp] : 0;
      const up = prev[i];
      const upLeft = i >= bpp ? prev[i - bpp] : 0;
      let v = row[i];
      if (type === 1) v += left;
      else if (type === 2) v += up;
      else if (type === 3) v += (left + up) >> 1;
      else if (type === 4) {
        const p = left + up - upLeft;
        const pa = Math.abs(p - left), pb = Math.abs(p - up), pc = Math.abs(p - upLeft);
        v += pa <= pb && pa <= pc ? left : pb <= pc ? up : upLeft;
      } else if (type !== 0) throw new FormatError(`PNG predictor row type ${type}`);
      cur[i] = v & 0xFF;
    }
    cur.copy(prev);
  }
  return out;
}

function lzw(data, earlyChange, budget) {
  const out = [];
  let table = [];
  const reset = () => { table = []; for (let i = 0; i < 256; i++) table.push([i]); table.push(null, null); };
  reset();
  let width = 9;
  let bitBuf = 0;
  let bits = 0;
  let prev = null;
  let produced = 0;
  for (const byte of data) {
    bitBuf = (bitBuf << 8) | byte;
    bits += 8;
    while (bits >= width) {
      const code = (bitBuf >> (bits - width)) & ((1 << width) - 1);
      bits -= width;
      bitBuf &= (1 << bits) - 1;
      if (code === 256) { reset(); width = 9; prev = null; continue; }
      if (code === 257) return Buffer.from(out);
      let entry;
      if (code < table.length && table[code]) entry = table[code];
      else if (code === table.length && prev) entry = [...prev, prev[0]];
      else throw new FormatError("LZW data is damaged");
      out.push(...entry);
      produced += entry.length;
      if (produced > budget.remainingBytes()) throw budget.bombTotal();
      if (prev) table.push([...prev, entry[0]]);
      prev = entry;
      const next = table.length + (earlyChange ? 1 : 0);
      if (next >= 1 << width && width < 12) width++;
    }
  }
  budget.spend(out.length);
  return Buffer.from(out);
}

function ascii85(data) {
  const s = data.toString("latin1").replace(/\s+/g, "").replace(/^<~/, "");
  const end = s.indexOf("~>");
  const body = end < 0 ? s : s.slice(0, end);
  const out = [];
  let group = [];
  const flush = (n) => {
    let v = 0;
    for (const c of group) v = v * 85 + c;
    const bytes = [(v >>> 24) & 0xFF, (v >>> 16) & 0xFF, (v >>> 8) & 0xFF, v & 0xFF];
    out.push(...bytes.slice(0, n));
  };
  for (const ch of body) {
    if (ch === "z" && group.length === 0) { out.push(0, 0, 0, 0); continue; }
    const c = ch.charCodeAt(0) - 33;
    if (c < 0 || c > 84) throw new FormatError("ASCII85 data holds a character outside its alphabet");
    group.push(c);
    if (group.length === 5) { flush(4); group = []; }
  }
  if (group.length) {
    const n = group.length - 1;
    while (group.length < 5) group.push(84);
    flush(n);
  }
  return Buffer.from(out);
}

function asciiHex(data) {
  const s = data.toString("latin1").replace(/\s+/g, "");
  const end = s.indexOf(">");
  const hex = end < 0 ? s : s.slice(0, end);
  if (/[^0-9A-Fa-f]/.test(hex)) throw new FormatError("ASCIIHex data holds a character that is not hex");
  return Buffer.from(hex.length % 2 ? `${hex}0` : hex, "hex");
}

function runLength(data) {
  const out = [];
  for (let i = 0; i < data.length;) {
    const n = data[i++];
    if (n === 128) break;
    if (n < 128) { out.push(...data.subarray(i, i + n + 1)); i += n + 1; }
    else { out.push(...new Array(257 - n).fill(data[i])); i++; }
  }
  return Buffer.from(out);
}
