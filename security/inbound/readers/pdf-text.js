// ============================================================
// OTLC Guardian - inbound-file check: PDF text reader
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// The text a PDF shows and carries, for the prompt-injection check:
//
//   - page and form text: the strings of the text operators (Tj, TJ,
//     ' and ") in every content stream and form XObject, decoded
//     through the font's ToUnicode CMap when it has one. A kerning
//     gap in a TJ array wide enough to be a space reads as one, and
//     each positioning operator starts a new line;
//   - every string in every object dictionary (document info,
//     annotations, form fields, bookmarks), also inside object streams;
//   - XMP and other XML metadata streams.
//
// A font name used on more than one page with different fonts is
// read with each of them, so a clash cannot hide text. Text in a
// composite font with no ToUnicode map is glyph numbers, not text;
// it is counted and reported, never guessed.
// ============================================================

import { xmlText } from "./markup.js";

const CP1252 = new TextDecoder("windows-1252");
const UTF16BE = new TextDecoder("utf-16be");
const UTF8 = new TextDecoder("utf-8");

// A gap in a TJ array, in thousandths of a text space unit, from
// which a reader sees a space between the strings either side.
const SPACE_GAP = 150;
const LINE_OPS = new Set(["Td", "TD", "Tm", "T*", "BT", "ET"]);

// ---------------------------------------------------------------------------
// LEXER
// ---------------------------------------------------------------------------

const DELIMITER = new Set([..."()<>[]{}/%"]);
const isSpace = (c) => c === 0x20 || c === 0x0A || c === 0x0D || c === 0x09 || c === 0x0C || c === 0x00;
const ESCAPES = { n: 0x0A, r: 0x0D, t: 0x09, b: 0x08, f: 0x0C };

/**
 * Tokens of PDF syntax: { t: "str", v: Buffer } | { t: "num", v } |
 * { t: "name", v } | { t: "op", v } | { t: "[" } | { t: "]" } |
 * { t: "<<" } | { t: ">>" }. Inline image data (ID ... EI) is skipped.
 */
function* tokens(buf, tick) {
  let p = 0;
  let steps = 0;
  while (p < buf.length) {
    if ((++steps & 0xFFF) === 0) tick();
    const c = buf[p];
    if (isSpace(c)) { p++; continue; }
    if (c === 0x25) { // % comment
      while (p < buf.length && buf[p] !== 0x0A && buf[p] !== 0x0D) p++;
      continue;
    }
    if (c === 0x28) { // ( literal string
      const out = [];
      let depth = 1;
      p++;
      while (p < buf.length) {
        const b = buf[p++];
        if (b === 0x5C) {
          const e = buf[p++];
          if (e === undefined) break;
          const ch = String.fromCharCode(e);
          if (ch in ESCAPES) out.push(ESCAPES[ch]);
          else if (e >= 0x30 && e <= 0x37) {
            let v = e - 0x30;
            for (let i = 0; i < 2 && buf[p] >= 0x30 && buf[p] <= 0x37; i++) v = v * 8 + buf[p++] - 0x30;
            out.push(v & 0xFF);
          } else if (e === 0x0D) { if (buf[p] === 0x0A) p++; } else if (e !== 0x0A) out.push(e);
        } else if (b === 0x28) { depth++; out.push(b); } else if (b === 0x29) {
          if (--depth === 0) break;
          out.push(b);
        } else out.push(b);
      }
      yield { t: "str", v: Buffer.from(out) };
      continue;
    }
    if (c === 0x3C && buf[p + 1] === 0x3C) { p += 2; yield { t: "<<" }; continue; }
    if (c === 0x3E && buf[p + 1] === 0x3E) { p += 2; yield { t: ">>" }; continue; }
    if (c === 0x3C) { // <hex string>
      const end = buf.indexOf(0x3E, p + 1);
      const stop = end < 0 ? buf.length : end;
      const hex = buf.toString("latin1", p + 1, stop).replace(/[^0-9A-Fa-f]/g, "");
      p = stop + 1;
      yield { t: "str", v: Buffer.from(hex.length % 2 ? `${hex}0` : hex, "hex") };
      continue;
    }
    if (c === 0x5B) { p++; yield { t: "[" }; continue; }
    if (c === 0x5D) { p++; yield { t: "]" }; continue; }
    if (c === 0x2F) { // /name
      const s = ++p;
      while (p < buf.length && !isSpace(buf[p]) && !DELIMITER.has(String.fromCharCode(buf[p]))) p++;
      yield { t: "name", v: buf.toString("latin1", s, p).replace(/#([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))) };
      continue;
    }
    const s = p;
    while (p < buf.length && !isSpace(buf[p]) && !DELIMITER.has(String.fromCharCode(buf[p]))) p++;
    if (p === s) { p++; continue; } // a stray delimiter: ) } {
    const word = buf.toString("latin1", s, p);
    if (/^[+-]?(?:\d+\.?\d*|\.\d+)$/.test(word)) { yield { t: "num", v: Number(word) }; continue; }
    if (word === "ID") {
      // Inline image data runs to an EI between white space.
      let q = p + 1;
      for (;;) {
        const ei = buf.indexOf("EI", q, "latin1");
        if (ei < 0) { q = buf.length; break; }
        if (isSpace(buf[ei - 1]) && (ei + 2 >= buf.length || isSpace(buf[ei + 2]))) { q = ei + 2; break; }
        q = ei + 2;
      }
      p = q;
      continue;
    }
    yield { t: "op", v: word };
  }
}

// ---------------------------------------------------------------------------
// FONTS
// ---------------------------------------------------------------------------

/**
 * A ToUnicode CMap: bfchar and bfrange entries, with the code lengths
 * its codespace ranges allow. Ranges are kept as ranges, never
 * expanded, so a CMap claiming 65,536 codes costs nothing.
 */
export function parseCmap(buf, tick) {
  const chars = new Map();
  const ranges = [];
  const lengths = new Set();
  const all = [...tokens(buf, tick)];
  const hexKey = (b) => b.toString("hex");
  const toText = (b) => UTF16BE.decode(b);
  for (let i = 0; i < all.length; i++) {
    const tok = all[i];
    if (tok.t !== "op") continue;
    if (tok.v === "begincodespacerange") {
      for (let j = i + 1; j + 1 < all.length && all[j].t === "str"; j += 2) lengths.add(all[j].v.length);
    } else if (tok.v === "beginbfchar") {
      for (let j = i + 1; j + 1 < all.length && all[j].t === "str" && all[j + 1].t === "str"; j += 2) {
        chars.set(hexKey(all[j].v), toText(all[j + 1].v));
        lengths.add(all[j].v.length);
      }
    } else if (tok.v === "beginbfrange") {
      let j = i + 1;
      while (j + 2 < all.length && all[j].t === "str" && all[j + 1].t === "str") {
        const lo = all[j].v;
        const hi = all[j + 1].v;
        lengths.add(lo.length);
        if (all[j + 2].t === "str") {
          ranges.push({ lo: lo.readUIntBE(0, Math.min(lo.length, 4)), hi: hi.readUIntBE(0, Math.min(hi.length, 4)), len: lo.length, dst: all[j + 2].v });
          j += 3;
        } else if (all[j + 2].t === "[") {
          const list = [];
          let k = j + 3;
          while (k < all.length && all[k].t === "str") list.push(toText(all[k++].v));
          ranges.push({ lo: lo.readUIntBE(0, Math.min(lo.length, 4)), hi: hi.readUIntBE(0, Math.min(hi.length, 4)), len: lo.length, list });
          j = k + 1;
        } else break;
      }
    }
  }
  const sizes = [...lengths].filter((n) => n >= 1 && n <= 4).sort((a, b) => a - b);
  if (sizes.length === 0) sizes.push(1);

  const lookup = (code, len) => {
    const hit = chars.get(code.toString(16).padStart(len * 2, "0"));
    if (hit !== undefined) return hit;
    for (const r of ranges) {
      if (r.len !== len || code < r.lo || code > r.hi) continue;
      if (r.list) return r.list[code - r.lo] ?? null;
      // The last byte of the destination counts up through the range.
      const dst = Buffer.from(r.dst);
      dst.writeUIntBE((dst.readUIntBE(Math.max(0, dst.length - 2), Math.min(2, dst.length)) + code - r.lo) & 0xFFFF,
        Math.max(0, dst.length - 2), Math.min(2, dst.length));
      return toText(dst);
    }
    return null;
  };

  return (bytes) => {
    let out = "";
    for (let p = 0; p < bytes.length;) {
      let done = false;
      for (const len of sizes) {
        if (p + len > bytes.length) break;
        const text = lookup(bytes.readUIntBE(p, len), len);
        if (text !== null) { out += text; p += len; done = true; break; }
      }
      if (!done) p += sizes[0];
    }
    return out;
  };
}

/** A PDF text string: UTF-16 or UTF-8 with a byte order mark, else PDFDocEncoding (read as Windows-1252). */
export function pdfTextString(bytes) {
  if (bytes.length >= 2 && bytes[0] === 0xFE && bytes[1] === 0xFF) return UTF16BE.decode(bytes.subarray(2));
  if (bytes.length >= 2 && bytes[0] === 0xFF && bytes[1] === 0xFE) return new TextDecoder("utf-16le").decode(bytes.subarray(2));
  if (bytes.length >= 3 && bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) return UTF8.decode(bytes.subarray(3));
  return CP1252.decode(bytes);
}

const refs = (text) => [...text.matchAll(/(\d+)\s+\d+\s+R\b/g)].map((m) => Number(m[1]));

/** The dictionary that opens at `from` ("<<"), balanced, as text. */
function dictAt(text, from) {
  let depth = 0;
  for (let i = from; i < text.length - 1; i++) {
    if (text[i] === "<" && text[i + 1] === "<") { depth++; i++; } else if (text[i] === ">" && text[i + 1] === ">") {
      depth--;
      i++;
      if (depth === 0) return text.slice(from + 2, i - 1);
    }
  }
  return text.slice(from + 2);
}

// ---------------------------------------------------------------------------
// READER
// ---------------------------------------------------------------------------

/**
 * @param {ReturnType<import("./pdf.js").readPdf>} doc an unencrypted PDF
 * @param {import("../limits.js").Budget} budget
 * @returns {{ texts: Array<{ label: string, text: string }>, undecodable: number }}
 */
export function pdfTexts(doc, budget) {
  const tick = () => budget.tick();
  const byNum = new Map();
  for (const o of doc.objects) byNum.set(o.num, o);

  // Font resource names to the fonts they stand for, across the file.
  const fontsByName = new Map();
  const addFonts = (dictText) => {
    for (const m of dictText.matchAll(/\/([^\s/<>[\]()]+)\s+(\d+)\s+\d+\s+R\b/g)) {
      if (!fontsByName.has(m[1])) fontsByName.set(m[1], new Set());
      fontsByName.get(m[1]).add(Number(m[2]));
    }
  };
  for (const o of doc.objects) {
    for (const m of o.dict.matchAll(/\/Font\s*(<<|(\d+)\s+\d+\s+R\b)/g)) {
      if (m[1] === "<<") addFonts(dictAt(o.dict, m.index + m[0].length - 2));
      else if (byNum.has(Number(m[2]))) addFonts(byNum.get(Number(m[2])).dict);
    }
  }

  const decoders = new Map();
  let undecodable = 0;
  const decoderFor = (num) => {
    if (decoders.has(num)) return decoders.get(num);
    const font = byNum.get(num);
    let decoder = (b) => CP1252.decode(b);
    if (font) {
      const tu = /\/ToUnicode\s+(\d+)\s+\d+\s+R\b/.exec(font.dict);
      const stream = tu ? byNum.get(Number(tu[1])) : null;
      const data = stream ? doc.decode(stream) : null;
      if (data) decoder = parseCmap(data, tick);
      else if (/\/Subtype\s*\/Type0\b/.test(font.dict)) decoder = null;
    }
    decoders.set(num, decoder);
    return decoder;
  };
  const decodersFor = (name) => {
    const fonts = fontsByName.get(name);
    if (!fonts) return [(b) => CP1252.decode(b)];
    return [...fonts].map(decoderFor);
  };

  // Content streams: page /Contents and form XObjects (also annotation appearances).
  const content = new Set();
  for (const o of doc.objects) {
    const c = /\/Contents\s*(\[[^\]]*\]|\d+\s+\d+\s+R\b)/.exec(o.dict);
    if (c && /\/Type\s*\/Page\b/.test(o.dict)) for (const n of refs(c[1])) content.add(n);
    if (o.raw && /\/Subtype\s*\/Form\b/.test(o.dict)) content.add(o.num);
  }

  const texts = [];
  for (const num of content) {
    const o = byNum.get(num);
    const data = o?.raw ? doc.decode(o) : null;
    if (!data) continue;
    const { text, missing } = showText(data, decodersFor, tick);
    undecodable += missing;
    if (text.trim()) texts.push({ label: `page text (object ${num})`, text });
  }

  const strings = [];
  for (const o of doc.objects) {
    tick();
    for (const tok of tokens(Buffer.from(o.dict, "latin1"), tick)) {
      if (tok.t === "str" && tok.v.length) strings.push(pdfTextString(tok.v));
    }
    if (o.raw && (/\/Type\s*\/Metadata\b/.test(o.dict) || /\/Subtype\s*\/XML\b/.test(o.dict))) {
      const data = doc.decode(o);
      if (data) {
        const xml = xmlText(UTF8.decode(data), { tick });
        texts.push({ label: `XMP metadata (object ${o.num})`, text: [xml.text, xml.attributes, xml.comments].join("\n") });
      }
    }
  }
  if (strings.length) texts.push({ label: "document strings", text: strings.join("\n") });
  return { texts, undecodable };
}

/** The text a content stream shows. */
function showText(data, decodersFor, tick) {
  let text = "";
  let missing = 0;
  let current = [(b) => CP1252.decode(b)];
  const operands = [];
  const arrays = [];
  const show = (pieces) => {
    // Each candidate font reads the whole run; more than one candidate
    // writes each reading on its own line.
    const readings = [];
    for (const decode of current) {
      if (!decode) { missing++; continue; }
      readings.push(pieces.map((x) => (typeof x === "number" ? (x <= -SPACE_GAP ? " " : "") : decode(x))).join(""));
    }
    text += readings.join("\n");
  };
  for (const tok of tokens(data, tick)) {
    if (tok.t === "[") { arrays.push([]); continue; }
    if (tok.t === "]") {
      const arr = arrays.pop() ?? [];
      (arrays.length ? arrays[arrays.length - 1] : operands).push({ t: "arr", v: arr });
      continue;
    }
    if (tok.t !== "op") {
      if (arrays.length) arrays[arrays.length - 1].push(tok.t === "num" || tok.t === "str" ? tok.v : null);
      else operands.push(tok);
      continue;
    }
    const op = tok.v;
    const last = operands[operands.length - 1];
    if (op === "Tf") {
      const name = operands.find((x) => x.t === "name");
      if (name) current = decodersFor(name.v);
    } else if (op === "Tj" && last?.t === "str") show([last.v]);
    else if ((op === "'" || op === '"') && last?.t === "str") { text += "\n"; show([last.v]); } else if (op === "TJ" && last?.t === "arr") {
      show(last.v.filter((x) => x !== null));
    } else if (LINE_OPS.has(op)) text += "\n";
    operands.length = 0;
    arrays.length = 0;
  }
  return { text, missing };
}
