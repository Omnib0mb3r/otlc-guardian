// ============================================================
// OTLC Guardian - inbound-file check: CAD exchange formats
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// Structure checks for the model files a customer sends beside a
// drawing: STL (ASCII and binary), STEP (ISO 10303-21) and IGES.
// None of them has a magic number worth the name, so each is known
// by its structure: a file is one of these only when it is built
// the way the format says. A file that merely carries the name is
// judged as what its bytes are (plain text, or an unknown format).
//
// STEP, IGES and ASCII STL are text and are read as text by the
// prompt-injection check. A binary STL holds only an 80-byte header
// and numbers; the header is read as text too.
// ============================================================

const STL_HEADER_BYTES = 80;
const STL_TRIANGLE_BYTES = 50;
const STL_FLOATS_PER_TRIANGLE = 12;
const EDGE_CHARS = 4096;

const IGES_LINE = 80;
// Column 73 names the section of each line, in this order.
const IGES_SECTIONS = "SGDPT";
const IGES_SECTION_COLUMN = 72;
const IGES_SEQUENCE = /^[ 0-9]{6}[0-9]$/;

/**
 * Binary STL: an 80-byte header, a triangle count, and exactly that
 * many 50-byte triangles of twelve finite floats each.
 * @param {Buffer} buf
 * @returns {boolean}
 */
export function isBinaryStl(buf) {
  const start = STL_HEADER_BYTES + 4;
  if (buf.length < start + STL_TRIANGLE_BYTES) return false;
  const triangles = buf.readUInt32LE(STL_HEADER_BYTES);
  if (start + triangles * STL_TRIANGLE_BYTES !== buf.length) return false;
  for (let offset = start; offset < buf.length; offset += STL_TRIANGLE_BYTES) {
    for (let i = 0; i < STL_FLOATS_PER_TRIANGLE; i++) {
      // Exponent bits all set: infinity or not a number, which no mesh holds.
      const high = offset + i * 4 + 3;
      if ((buf[high] & 0x7F) === 0x7F && (buf[high - 1] & 0x80) === 0x80) return false;
    }
  }
  return true;
}

/** The header of a binary STL, which is free text. */
export const stlHeader = (buf) => buf.subarray(0, STL_HEADER_BYTES);

/**
 * The CAD text format `text` is built as, or null.
 * @param {string} text the whole decoded file
 * @returns {"step"|"iges"|"stl-ascii"|null}
 */
export function cadTextType(text) {
  const head = text.slice(0, EDGE_CHARS).trimStart();
  const tail = text.slice(-EDGE_CHARS).trimEnd();
  if (head.startsWith("ISO-10303-21;")) {
    return /\bHEADER\s*;/.test(head) && text.includes("ENDSEC;") && tail.endsWith("END-ISO-10303-21;") ? "step" : null;
  }
  if (/^solid\b/.test(head)) {
    const lastLine = tail.slice(tail.lastIndexOf("\n") + 1).trimStart();
    const body = head.slice(head.indexOf("\n") + 1).trimStart();
    return /^endsolid\b/.test(lastLine) && /^(?:facet\s+normal\b|endsolid\b)/.test(body) ? "stl-ascii" : null;
  }
  return isIges(text) ? "iges" : null;
}

/**
 * IGES fixed format: every line is 80 columns, column 73 runs through
 * the sections S, G, D, P and T in that order, columns 74 to 80 are a
 * sequence number, and the file ends with its one T line.
 */
function isIges(text) {
  if (text.length < IGES_LINE || text[IGES_SECTION_COLUMN] !== "S") return false;
  let section = 0;
  let terminators = 0;
  let start = 0;
  while (start < text.length) {
    let end = text.indexOf("\n", start);
    if (end === -1) end = text.length;
    const lineEnd = end > start && text[end - 1] === "\r" ? end - 1 : end;
    if (lineEnd === start && end === text.length) break; // the newline that ends the file
    if (lineEnd - start !== IGES_LINE) return false;
    const at = IGES_SECTIONS.indexOf(text[start + IGES_SECTION_COLUMN]);
    if (at < section || terminators > 0) return false;
    section = at;
    if (!IGES_SEQUENCE.test(text.slice(start + IGES_SECTION_COLUMN + 1, lineEnd))) return false;
    if (IGES_SECTIONS[at] === "T") terminators++;
    start = end + 1;
  }
  return terminators === 1;
}
