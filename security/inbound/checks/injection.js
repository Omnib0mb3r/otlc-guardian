// ============================================================
// OTLC Guardian - inbound-file check 7: prompt injection
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// Text aimed at an AI reader. Every text a file carries goes through
// scan() from security/01-injection-guard.js, the rule set the hooks
// use; there is no second pattern list here. Text is pulled from:
// plain text, XML (text, CDATA, comments, attribute values), HTML and
// SVG (visible and hidden text, alt, title and aria-label), Office
// documents (every XML part, legacy streams through their printable
// runs, RTF), PDF (page text through ToUnicode maps, every dictionary
// string, XMP), image metadata (PNG text chunks, JPEG comment, EXIF,
// IPTC, XMP), and the mail's subject, from and original name.
//
// Text longer than scan()'s one-million-character cap is read in
// overlapping windows, so nothing is left unscanned.
//
// Every rule hit holds, with the rule id and the matched text, except
// GUARD-INJ-UNICODE, which is mapped by character (Lex, 2026-11-12):
//
//   hold: characters used to smuggle text: Unicode tag characters
//         (U+E0000 to U+E007F), bidi overrides and isolates (U+202A to
//         U+202E, U+2066 to U+2069), the deprecated format characters
//         U+206A to U+206F, a run of variation selectors, and a run of
//         zero-width characters inside a word or long enough to encode
//         hidden text;
//   info: typographic ones on their own: soft hyphens, U+202F and
//         other spaces, a lone ZWNJ or ZWJ (mail padding, emoji and
//         joining scripts), LRM and RLM, a byte order mark. They are
//         reported and do not hold.
//
// HTML and SVG active content (scripts, event handlers, forms,
// frames, plug-ins, script and data URLs) holds as
// markup-active-content (contract v1 item 7).
// ============================================================

import { scan } from "../../01-injection-guard.js";
import { decodeText, printableRuns } from "../readers/text.js";
import { xmlText, readMarkup } from "../readers/markup.js";
import { imageTexts } from "../readers/image.js";
import { pdfTexts } from "../readers/pdf-text.js";

export const WINDOW = 1_000_000;
export const OVERLAP = 2_048;
const MATCH_MAX = 80;
const META_FIELDS = ["subject", "from", "original_name"];

// Office XML: words are split across runs, so only these elements
// separate them.
const OFFICE_BLOCKS = new Set([
  "p", "br", "cr", "tab", "tc", "tr", "tbl", "si", "c", "row", "txbxcontent", "comment", "footnote",
  "endnote", "hdr", "ftr", "sp", "h", "line-break", "s", "table-cell", "table-row", "list-item", "annotation",
]);
const OFFICE_ATTRIBUTES = new Set(["descr", "title"]);
const OFFICE_DOCUMENTS = new Set(["ooxml-word", "ooxml-excel", "ooxml-powerpoint", "ooxml", "odf"]);

/**
 * Check 7. The meta fields are read once, with the top-level file.
 * @param {import("../index.js").Inspection} ctx
 * @param {Buffer} buf
 * @param {import("../index.js").Node} node
 */
export function checkInjection(ctx, buf, node) {
  if (node.top) {
    for (const field of META_FIELDS) {
      const value = ctx.meta[field];
      if (value) scanText(ctx, { metaField: `meta.${field}` }, `meta ${field}`, value);
    }
  }
  for (const { label, text } of textsOf(ctx, buf, node)) scanText(ctx, node, label, text);
}

/** The texts one node carries, labelled for the reason detail. */
function textsOf(ctx, buf, node) {
  const tick = () => ctx.budget.tick();
  const type = node.type;
  if (type === "text") {
    const decoded = decodeText(buf);
    return decoded ? [{ label: "text", text: decoded.text }] : [];
  }
  if (type === "xml") return xmlTexts(decodeText(buf)?.text ?? "", "", { tick });
  if (type === "html" || type === "svg") return markupTexts(ctx, node, decodeText(buf)?.text ?? "");
  if (OFFICE_DOCUMENTS.has(type) && node.parts) return officeTexts(ctx, node);
  if (type.startsWith("cfb") && node.cfb) {
    return node.cfb.entries.filter((e) => e.type === "stream").map((e) => {
      tick();
      return { label: `document stream ${e.path}`, text: printableRuns(node.cfb.read(e)).join("\n") };
    });
  }
  if (type === "rtf") return [{ label: "RTF text", text: rtfText(buf.toString("latin1")) }];
  if (type === "pdf" && node.pdf && !node.pdf.encrypted) {
    const { texts, undecodable } = pdfTexts(node.pdf, ctx.budget);
    if (undecodable) {
      ctx.report("injection", "info", "pdf-text-unmapped",
        `${undecodable} text run${undecodable === 1 ? "" : "s"} in a font with no Unicode map; glyph numbers, not text, were not read`, node);
    }
    return texts;
  }
  return imageTexts(buf, type, ctx.budget);
}

function xmlTexts(src, prefix, options) {
  const { text, attributes, comments } = xmlText(src, options);
  return [
    { label: `${prefix}XML text`, text },
    { label: `${prefix}XML attribute values`, text: attributes },
    { label: `${prefix}XML comments`, text: comments },
  ];
}

function markupTexts(ctx, node, src) {
  const doc = readMarkup(src, { tick: () => ctx.budget.tick() });
  for (const what of doc.active) {
    ctx.report("injection", "hold", "markup-active-content", `${node.part ? `${node.part}: ` : ""}${what}`, node);
  }
  return [
    { label: "visible text", text: doc.visible },
    { label: "hidden text", text: doc.hidden },
    { label: "HTML comments", text: doc.comments },
    { label: "attribute text (alt, title, aria-label)", text: doc.attributes },
  ];
}

function officeTexts(ctx, node) {
  const tick = () => ctx.budget.tick();
  const out = [];
  for (const [name, data] of node.parts) {
    tick();
    if (/\.(?:xml|vml)$/i.test(name)) {
      const content = /^(?:word|xl|ppt)\//i.test(name) || /^(?:content|styles)\.xml$/i.test(name);
      const options = content ? { blocks: OFFICE_BLOCKS, attributes: OFFICE_ATTRIBUTES, tick } : { tick };
      out.push(...xmlTexts(decodeText(data)?.text ?? "", `${name}: `, options));
    } else {
      const head = data.subarray(0, 4);
      const type = head[0] === 0x89 && head[1] === 0x50 ? "png" : head[0] === 0xFF && head[1] === 0xD8 ? "jpeg" : null;
      if (type) out.push(...imageTexts(data, type, ctx.budget).map((t) => ({ ...t, label: `${name}: ${t.label}` })));
    }
  }
  return out;
}

/** RTF with its control words and groups taken out. */
function rtfText(src) {
  return src
    .replace(/\\'([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\u(-?\d+)\??/g, (_, n) => String.fromCharCode((Number(n) + 0x10000) % 0x10000))
    .replace(/\\(?:par|line|tab|cell|row|sect|page)\b ?/g, "\n")
    .replace(/\\[a-z]+-?\d* ?/gi, "")
    .replace(/[{}]/g, "");
}

// ---------------------------------------------------------------------------
// SCANNING
// ---------------------------------------------------------------------------

/** Windows of at most WINDOW characters, each overlapping the one before by OVERLAP. */
export function* windows(text) {
  if (text.length <= WINDOW) {
    yield text;
    return;
  }
  for (let start = 0; start < text.length; start += WINDOW - OVERLAP) {
    yield text.slice(start, start + WINDOW);
    if (start + WINDOW >= text.length) return;
  }
}

const clipMatch = (s) => {
  const flat = String(s).replace(/\s+/g, " ").trim();
  return flat.length > MATCH_MAX ? `${flat.slice(0, MATCH_MAX)}...` : flat;
};

function scanText(ctx, node, label, text) {
  if (!text || !text.trim()) return;
  const where = node.part ? `${node.part} > ${label}` : label;
  let unicodeRule = false;
  for (const window of windows(text)) {
    ctx.budget.tick();
    for (const v of scan(window, "injection").violations) {
      if (v.id === "GUARD-INJ-UNICODE") {
        unicodeRule = true;
        continue;
      }
      ctx.report("injection", "hold", "prompt-injection", `${v.id} in ${where}: "${clipMatch(v.matched)}"`, node);
    }
  }
  const invisible = classifyInvisible(text);
  for (const what of invisible.smuggling) {
    ctx.report("injection", "hold", "prompt-injection", `GUARD-INJ-UNICODE in ${where}: ${what}`, node);
  }
  if (invisible.smuggling.length === 0 && unicodeRule) {
    const list = invisible.typographic.length ? invisible.typographic.join(", ") : "invisible characters";
    ctx.report("injection", "info", "invisible-characters", `typographic invisible characters in ${where} (${list}); not held`, node);
  }
}

// ---------------------------------------------------------------------------
// INVISIBLE CHARACTERS
// ---------------------------------------------------------------------------

const isTag = (cp) => cp >= 0xE0000 && cp <= 0xE007F;
const isBidiControl = (cp) => (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069);
const isDeprecatedFormat = (cp) => cp >= 0x206A && cp <= 0x206F;
const isVariationSelector = (cp) => (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF);
const isZeroWidth = (cp) => (cp >= 0x200B && cp <= 0x200D) || (cp >= 0x2060 && cp <= 0x2064) || cp === 0xFEFF || cp === 0x180E;
const WORD = /[\p{L}\p{N}]/u;
// A run this long encodes at least one hidden byte, wherever it sits.
const HIDDEN_RUN = 8;
const TYPOGRAPHIC = /[\p{Cf}\u2028\u2029\u202F]/u;
const hex = (cp) => `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;

/**
 * Sorts the invisible characters in `text` into those that smuggle
 * text (they hold) and typographic ones (info).
 * @param {string} text
 * @returns {{ smuggling: string[], typographic: string[] }}
 */
export function classifyInvisible(text) {
  const found = { tag: 0, bidi: 0, deprecated: 0, selectorRun: 0, zeroWidthRun: 0 };
  const typographic = new Map();
  const count = (cp) => typographic.set(hex(cp), (typographic.get(hex(cp)) ?? 0) + 1);
  const at = (i) => text.codePointAt(i);
  const step = (i) => (at(i) > 0xFFFF ? 2 : 1);
  const isWordAt = (i) => i >= 0 && i < text.length && WORD.test(String.fromCodePoint(at(i)));
  // The code point that ends just before index i.
  const before = (i) => (i >= 2 && at(i - 2) > 0xFFFF ? i - 2 : i - 1);
  // Only the characters that can matter are looked at one by one; the
  // rest of the text is skipped by the regular expression engine.
  const candidates = /[\p{Cf}\u2028\u2029\u202F\uFE00-\uFE0F\u{E0100}-\u{E01EF}]/gu;
  for (let m = candidates.exec(text); m; m = candidates.exec(text)) {
    const i = m.index;
    const cp = at(i);
    if (isTag(cp)) found.tag++;
    else if (isBidiControl(cp)) found.bidi++;
    else if (isDeprecatedFormat(cp)) found.deprecated++;
    else if (isVariationSelector(cp)) {
      let j = i;
      while (j < text.length && isVariationSelector(at(j))) j += step(j);
      if ([...text.slice(i, j)].length >= 2) found.selectorRun++;
      candidates.lastIndex = j;
    } else if (isZeroWidth(cp)) {
      let j = i;
      const run = [];
      while (j < text.length && isZeroWidth(at(j))) { run.push(at(j)); j += step(j); }
      if (run.length >= HIDDEN_RUN || (run.length >= 2 && (isWordAt(before(i)) || isWordAt(j)))) found.zeroWidthRun++;
      else run.forEach(count);
      candidates.lastIndex = j;
    } else if (TYPOGRAPHIC.test(m[0])) {
      count(cp);
    }
  }
  const smuggling = [];
  if (found.tag) smuggling.push(`${found.tag} Unicode tag character${found.tag === 1 ? "" : "s"} (hidden ASCII)`);
  if (found.bidi) smuggling.push(`${found.bidi} bidi override or isolate character${found.bidi === 1 ? "" : "s"}`);
  if (found.deprecated) smuggling.push(`${found.deprecated} deprecated invisible format character${found.deprecated === 1 ? "" : "s"}`);
  if (found.selectorRun) smuggling.push(`${found.selectorRun} run${found.selectorRun === 1 ? "" : "s"} of variation selectors`);
  if (found.zeroWidthRun) smuggling.push(`${found.zeroWidthRun} run${found.zeroWidthRun === 1 ? "" : "s"} of zero-width characters spelling hidden text`);
  return { smuggling, typographic: [...typographic].map(([cp, n]) => `${cp} x${n}`) };
}
