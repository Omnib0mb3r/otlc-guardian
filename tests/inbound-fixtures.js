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
// DEFENDER RUNNERS (mocked; the real one is opt-in)
// ---------------------------------------------------------------------------

export const defenderClean = () => ({ status: "clean", detail: "no threats (mock)" });
export const defenderThreat = () => ({ status: "threat", detail: "Virus:DOS/EICAR_Test_File (mock)" });
export const defenderUnavailable = () => ({ status: "unavailable", detail: "MpCmdRun.exe not found (mock)" });
export const defenderError = () => ({ status: "error", detail: "exit code 0x80508023 (mock)" });
