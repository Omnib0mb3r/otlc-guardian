// ============================================================
// OTLC Guardian - inbound-file check: image text reader
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// The text an image carries beside its pixels, which a model reading
// the file may be given: PNG tEXt, zTXt and iTXt chunks; JPEG
// comments, EXIF and Photoshop (IPTC) blocks, and XMP. Pixels are
// never decoded. A damaged chunk or segment ends the walk; the type
// check has already judged the format. A compressed text chunk that
// does not inflate is unreadable text, and holds.
// ============================================================

import { inflateLimited } from "../limits.js";
import { printableRuns } from "./text.js";
import { xmlText } from "./markup.js";
import { FormatError } from "../errors.js";

const LATIN1 = new TextDecoder("latin1");
const UTF8 = new TextDecoder("utf-8");
const XMP_ID = "http://ns.adobe.com/xap/1.0/\0";

/**
 * @param {Buffer} buf
 * @param {string} type "png" or "jpeg"; any other type has no text read
 * @param {import("../limits.js").Budget} budget
 * @returns {Array<{ label: string, text: string }>}
 */
export function imageTexts(buf, type, budget) {
  if (type === "png") return pngTexts(buf, budget);
  if (type === "jpeg") return jpegTexts(buf, budget);
  return [];
}

function pngTexts(buf, budget) {
  const out = [];
  let p = 8;
  while (p + 12 <= buf.length) {
    budget.tick();
    const length = buf.readUInt32BE(p);
    const type = buf.toString("latin1", p + 4, p + 8);
    const data = buf.subarray(p + 8, Math.min(buf.length, p + 8 + length));
    p += 12 + length;
    if (type === "IEND") break;
    const nul = data.indexOf(0);
    if (nul < 0) continue;
    const keyword = LATIN1.decode(data.subarray(0, nul));
    if (type === "tEXt") {
      out.push({ label: `PNG text "${keyword}"`, text: LATIN1.decode(data.subarray(nul + 1)) });
    } else if (type === "zTXt") {
      out.push({ label: `PNG text "${keyword}"`, text: LATIN1.decode(inflate(data.subarray(nul + 2), budget)) });
    } else if (type === "iTXt") {
      const compressed = data[nul + 1] === 1;
      const langEnd = data.indexOf(0, nul + 3);
      const transEnd = langEnd < 0 ? -1 : data.indexOf(0, langEnd + 1);
      if (transEnd < 0) continue;
      const translated = UTF8.decode(data.subarray(langEnd + 1, transEnd));
      const body = data.subarray(transEnd + 1);
      const text = UTF8.decode(compressed ? inflate(body, budget) : body);
      out.push({ label: `PNG text "${keyword}"`, text: translated ? `${translated}\n${text}` : text });
    }
  }
  return out;
}

function jpegTexts(buf, budget) {
  const out = [];
  let p = 2;
  while (p + 4 <= buf.length) {
    budget.tick();
    if (buf[p] !== 0xFF) break;
    const marker = buf[p + 1];
    if (marker === 0xFF) { p++; continue; }
    // Start of scan and end of image: no more metadata segments follow.
    if (marker === 0xDA || marker === 0xD9) break;
    const length = buf.readUInt16BE(p + 2);
    const data = buf.subarray(p + 4, Math.min(buf.length, p + 2 + length));
    p += 2 + length;
    if (marker === 0xFE) {
      out.push({ label: "JPEG comment", text: decodeComment(data) });
    } else if (marker === 0xE1 && data.subarray(0, XMP_ID.length).toString("latin1") === XMP_ID) {
      const xmp = xmlText(UTF8.decode(data.subarray(XMP_ID.length)), { tick: () => budget.tick() });
      out.push({ label: "XMP metadata", text: [xmp.text, xmp.attributes, xmp.comments].join("\n") });
    } else if (marker === 0xE1 && data.subarray(0, 6).toString("latin1") === "Exif\0\0") {
      out.push({ label: "EXIF metadata", text: printableRuns(data.subarray(6), 4).join("\n") });
    } else if (marker === 0xED) {
      out.push({ label: "IPTC metadata", text: printableRuns(data, 4).join("\n") });
    }
  }
  return out;
}

/** A JPEG comment is often UTF-8 though the format says Latin-1. */
function decodeComment(data) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(data);
  } catch {
    // Not UTF-8: every byte has a Latin-1 reading.
    return LATIN1.decode(data);
  }
}

function inflate(data, budget) {
  try {
    return inflateLimited("zlib", data, budget, { tolerant: true });
  } catch (error) {
    if (error?.name === "LimitError") throw error;
    // Text that cannot be read is not judged, so it holds.
    throw new FormatError(`a compressed PNG text chunk does not inflate (${error.message})`);
  }
}
