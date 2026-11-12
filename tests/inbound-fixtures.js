/**
 * ============================================================
 * OTLC GUARDIAN - inbound-check test fixtures
 * // tests · onthelevelconcepts.com
 * Version: 1.5.0
 * ============================================================
 *
 * Builders for the files tests/inbound.test.js judges. Every file
 * here is Guardian-made, written byte by byte from the format
 * specifications: no customer, employer or third-party file is in
 * this repository (it is public). Hostile samples are inert: a
 * macro project with no code, a PDF script that only calls
 * app.alert, an executable header with no program behind it.
 *
 * Built in memory. The test writes them to an OS temp folder only.
 * ============================================================
 */

import zlib from "zlib";

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const u32be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };

// ---------------------------------------------------------------------------
// EXECUTABLES (headers only, no program)
// ---------------------------------------------------------------------------

/** An MZ header whose e_lfanew points at a PE signature. Not runnable. */
export function pe() {
  const b = Buffer.alloc(0x80);
  b.write("MZ", 0, "latin1");
  b.writeUInt32LE(0x40, 0x3C);
  b.write("PE\0\0", 0x40, "latin1");
  return b;
}

export const elf = () => Buffer.concat([Buffer.from([0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0]), Buffer.alloc(56)]);
export const lnk = () => Buffer.concat([Buffer.from([0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0x00]), Buffer.alloc(68)]);
export const javaClass = () => Buffer.from([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x41, 0, 0]);

// ---------------------------------------------------------------------------
// IMAGES
// ---------------------------------------------------------------------------

function pngChunk(type, data) {
  const head = Buffer.from(type, "latin1");
  return Buffer.concat([u32be(data.length), head, data, u32be(zlib.crc32(Buffer.concat([head, data])))]);
}

/**
 * A 1x1 grey PNG. `text` adds tEXt chunks ({ keyword: value }),
 * `ztext` adds compressed zTXt chunks.
 */
export function png({ text = {}, ztext = {} } = {}) {
  const ihdr = Buffer.concat([u32be(1), u32be(1), Buffer.from([8, 0, 0, 0, 0])]);
  const idat = zlib.deflateSync(Buffer.from([0, 0x80]));
  const chunks = [pngChunk("IHDR", ihdr)];
  for (const [k, v] of Object.entries(text)) chunks.push(pngChunk("tEXt", Buffer.from(`${k}\0${v}`, "latin1")));
  for (const [k, v] of Object.entries(ztext)) {
    chunks.push(pngChunk("zTXt", Buffer.concat([Buffer.from(`${k}\0\0`, "latin1"), zlib.deflateSync(Buffer.from(v, "latin1"))])));
  }
  chunks.push(pngChunk("IDAT", idat), pngChunk("IEND", Buffer.alloc(0)));
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), ...chunks]);
}

function jpegSegment(marker, data) {
  const len = Buffer.alloc(2);
  len.writeUInt16BE(data.length + 2);
  return Buffer.concat([Buffer.from([0xFF, marker]), len, data]);
}

/**
 * JPEG segment structure (SOI, optional COM, EXIF and XMP, SOS, EOI).
 * The scan data is a stub: enough for a reader of the format, not a
 * picture. tests/fixtures/inbound/clean.jpg is a real one.
 */
export function jpeg({ comment, exifText, xmp } = {}) {
  const parts = [Buffer.from([0xFF, 0xD8])];
  parts.push(jpegSegment(0xE0, Buffer.from("JFIF\0\x01\x01\0\0\x01\0\x01\0\0", "latin1")));
  if (comment) parts.push(jpegSegment(0xFE, Buffer.from(comment, "latin1")));
  if (exifText) {
    // A TIFF header with one ImageDescription (0x010E) ASCII entry.
    const text = Buffer.from(`${exifText}\0`, "latin1");
    const ifd = Buffer.concat([u16(1), u16(0x010E), u16(2), u32(text.length), u32(26), u32(0)]);
    const tiff = Buffer.concat([Buffer.from("II*\0", "latin1"), u32(8), ifd, text]);
    parts.push(jpegSegment(0xE1, Buffer.concat([Buffer.from("Exif\0\0", "latin1"), tiff])));
  }
  if (xmp) parts.push(jpegSegment(0xE1, Buffer.from(`http://ns.adobe.com/xap/1.0/\0${xmp}`, "utf8")));
  parts.push(jpegSegment(0xDA, Buffer.from([1, 1, 0, 0, 0x3F, 0])), Buffer.from([0x12, 0x34]), Buffer.from([0xFF, 0xD9]));
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// ARCHIVES
// ---------------------------------------------------------------------------

/**
 * A zip written to APPNOTE 6.3.10. Each entry: { name, data, method
 * (8 deflate, default; 0 stored; any other number is written as is),
 * symlink, encrypted (flag bit 0), aes (method 99 with its 0x9901
 * field), localName (a different name in the local header), crc
 * (overrides the real one) }.
 */
export function zip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const e of entries) {
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data ?? "", "utf8");
    const method = e.aes ? 99 : (e.method ?? 8);
    const stored = method === 8 ? zlib.deflateRawSync(data) : data;
    const flags = (e.encrypted ? 0x0001 : 0) | 0x0800;
    const crc = e.crc ?? zlib.crc32(data);
    const name = Buffer.from(e.name, "utf8");
    const localName = Buffer.from(e.localName ?? e.name, "utf8");
    const extra = e.aes ? Buffer.concat([u16(0x9901), u16(7), u16(2), Buffer.from("AE"), Buffer.from([3]), u16(8)]) : Buffer.alloc(0);
    const local = Buffer.concat([
      u32(0x04034b50), u16(20), u16(flags), u16(method), u16(0), u16(0x21),
      u32(crc), u32(stored.length), u32(data.length), u16(localName.length), u16(extra.length), localName, extra,
    ]);
    const madeBy = e.symlink ? (3 << 8) | 20 : 20;
    const attr = e.symlink ? (0o120777 << 16) >>> 0 : 0;
    centrals.push(Buffer.concat([
      u32(0x02014b50), u16(madeBy), u16(20), u16(flags), u16(method), u16(0), u16(0x21),
      u32(crc), u32(stored.length), u32(data.length), u16(name.length), u16(extra.length), u16(0),
      u16(0), u16(0), u32(attr), u32(offset), name, extra,
    ]));
    locals.push(local, stored);
    offset += local.length + stored.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.concat([
    u32(0x06054b50), u16(0), u16(0), u16(entries.length), u16(entries.length), u32(cd.length), u32(offset), u16(0),
  ]);
  return Buffer.concat([...locals, cd, eocd]);
}

/** A tar (ustar) of { name, data, type ("0" file, "2" symlink, "1" hardlink, "3" device), linkname }. */
export function tar(entries) {
  const blocks = [];
  for (const e of entries) {
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data ?? "", "utf8");
    const h = Buffer.alloc(512);
    h.write(e.name, 0, 100, "utf8");
    h.write("0000644\0", 100, "latin1");
    h.write("0000000\0", 108, "latin1");
    h.write("0000000\0", 116, "latin1");
    h.write(`${data.length.toString(8).padStart(11, "0")}\0`, 124, "latin1");
    h.write("00000000000\0", 136, "latin1");
    h.write("        ", 148, "latin1");
    h.write(e.type ?? "0", 156, "latin1");
    if (e.linkname) h.write(e.linkname, 157, 100, "utf8");
    h.write("ustar\0" + "00", 257, "latin1");
    let sum = 0;
    for (const b of h) sum += b;
    h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "latin1");
    blocks.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

/** gzip with the member name stored in the header. */
export function gzip(data, name) {
  const body = zlib.gzipSync(Buffer.isBuffer(data) ? data : Buffer.from(data));
  if (!name) return body;
  // Rebuild the header with FNAME set: same deflate stream and trailer.
  const header = Buffer.from([0x1F, 0x8B, 8, 0x08, 0, 0, 0, 0, 0, 0xFF]);
  return Buffer.concat([header, Buffer.from(`${name}\0`, "latin1"), body.subarray(10)]);
}

// ---------------------------------------------------------------------------
// DEFENDER RUNNERS (mocked; the real one is opt-in)
// ---------------------------------------------------------------------------

export const defenderClean = () => ({ status: "clean", detail: "no threats (mock)" });
export const defenderThreat = () => ({ status: "threat", detail: "Virus:DOS/EICAR_Test_File (mock)" });
export const defenderUnavailable = () => ({ status: "unavailable", detail: "MpCmdRun.exe not found (mock)" });
export const defenderError = () => ({ status: "error", detail: "exit code 0x80508023 (mock)" });
