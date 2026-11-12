// ============================================================
// OTLC Guardian - inbound-file check: text reader
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// Decides whether bytes are text and decodes them. A file is text
// when it carries a Unicode byte order mark, or when it holds no
// NUL byte and almost no other control characters. UTF-8 is tried
// first; bytes that are not valid UTF-8 are read as Windows-1252,
// which every byte value decodes under.
// ============================================================

const UTF8_STRICT = new TextDecoder("utf-8", { fatal: true });
const CP1252      = new TextDecoder("windows-1252");
const UTF16LE     = new TextDecoder("utf-16le");
const UTF16BE     = new TextDecoder("utf-16be");

// Share of control characters (other than tab, newline, carriage
// return, form feed and escape) above which bytes are not text.
const CONTROL_SHARE = 0.01;
const SAMPLE_BYTES  = 64 * 1024;

/**
 * @param {Buffer} buf
 * @returns {{ text: string, encoding: string } | null} null when the bytes are not text
 */
export function decodeText(buf) {
  if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) {
    return decodeUtf8OrLegacy(buf.subarray(3), "utf-8-bom");
  }
  if (buf.length >= 2 && buf[0] === 0xFF && buf[1] === 0xFE) {
    return { text: UTF16LE.decode(buf.subarray(2)), encoding: "utf-16le" };
  }
  if (buf.length >= 2 && buf[0] === 0xFE && buf[1] === 0xFF) {
    return { text: UTF16BE.decode(buf.subarray(2)), encoding: "utf-16be" };
  }
  const utf16 = utf16WithoutBom(buf);
  if (utf16) return { text: utf16.decode(buf), encoding: utf16.encoding };

  if (!looksLikeText(buf)) return null;
  return decodeUtf8OrLegacy(buf, "utf-8");
}

function decodeUtf8OrLegacy(buf, label) {
  try {
    return { text: UTF8_STRICT.decode(buf), encoding: label };
  } catch {
    // Not valid UTF-8: every byte has a Windows-1252 reading, so the
    // fallback cannot fail. The encoding is reported, not hidden.
    return { text: CP1252.decode(buf), encoding: "windows-1252" };
  }
}

function looksLikeText(buf) {
  const sample = buf.subarray(0, Math.min(buf.length, SAMPLE_BYTES));
  if (sample.length === 0) return true;
  let control = 0;
  for (const byte of sample) {
    if (byte === 0) return false;
    if (byte < 0x20 && byte !== 0x09 && byte !== 0x0A && byte !== 0x0D && byte !== 0x0C && byte !== 0x1B) control++;
    else if (byte === 0x7F) control++;
  }
  return control / sample.length <= CONTROL_SHARE;
}

/**
 * UTF-16 text written without a byte order mark has a NUL in every
 * other byte for ASCII content. Requires that pattern on nearly all
 * of the sample, so binary data with scattered NULs is not taken for it.
 */
function utf16WithoutBom(buf) {
  const n = Math.min(buf.length, SAMPLE_BYTES) & ~1;
  if (n < 8) return null;
  let evenZero = 0;
  let oddZero = 0;
  for (let i = 0; i < n; i += 2) {
    if (buf[i] === 0) evenZero++;
    if (buf[i + 1] === 0) oddZero++;
  }
  const pairs = n / 2;
  if (oddZero / pairs > 0.9 && evenZero / pairs < 0.05) return { decode: (b) => UTF16LE.decode(b), encoding: "utf-16le" };
  if (evenZero / pairs > 0.9 && oddZero / pairs < 0.05) return { decode: (b) => UTF16BE.decode(b), encoding: "utf-16be" };
  return null;
}

/**
 * Printable runs in binary data: Windows-1252 runs and UTF-16LE runs
 * of at least `min` characters. Used where a format keeps its text in
 * a binary stream the check does not fully parse (legacy Office
 * streams, EXIF), so text written there is still read.
 *
 * @param {Buffer} buf
 * @param {number} [min]
 * @returns {string[]}
 */
export function printableRuns(buf, min = 6) {
  const runs = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const b = i < buf.length ? buf[i] : 0;
    const printable = (b >= 0x20 && b < 0x7F) || b === 0x09 || b >= 0xA0;
    if (printable) {
      if (start < 0) start = i;
    } else {
      if (start >= 0 && i - start >= min) runs.push(CP1252.decode(buf.subarray(start, i)));
      start = -1;
    }
  }
  for (const parity of [0, 1]) {
    let runStart = -1;
    for (let i = parity; i <= buf.length; i += 2) {
      // Past the last whole pair the code is 0, which ends any open run.
      const code = i + 1 < buf.length ? buf[i] | (buf[i + 1] << 8) : 0;
      const printable = (code >= 0x20 && code !== 0x7F && code < 0xD800) || code === 0x09;
      if (printable) {
        if (runStart < 0) runStart = i;
      } else {
        if (runStart >= 0 && (i - runStart) / 2 >= min) {
          const text = UTF16LE.decode(buf.subarray(runStart, i));
          // A run of ASCII bytes read two at a time decodes to CJK noise.
          // Keep a UTF-16 run only when most of it is in the Latin range,
          // which is where real UTF-16LE text from Office sits.
          if (/^[\u0009 -ɏ -⁯]+$/.test(text)) runs.push(text);
        }
        runStart = -1;
      }
    }
  }
  return runs;
}
