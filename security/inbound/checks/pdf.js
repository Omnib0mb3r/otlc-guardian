// ============================================================
// OTLC Guardian - inbound-file check 4: PDF
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// Block: JavaScript (/JavaScript, /JS, also inside object streams and
// under #xx-escaped names) and /Launch, the two ways a PDF runs
// something.
// Hold: /RichMedia, /SubmitForm, /GoToR and /GoToE (other files),
// /ImportData, XFA forms, and a stream Guardian cannot decode.
// Every embedded file (/EmbeddedFile, /EF) is judged as a file of its
// own. An encrypted PDF goes to check 6 and holds: its strings and
// streams cannot be read, though its names still are.
// ============================================================

import { readPdf } from "../readers/pdf.js";

const BLOCK_KEYS = [
  { re: /\/(?:JavaScript|JS)(?![A-Za-z0-9])/, code: "pdf-javascript", what: "JavaScript" },
  { re: /\/Launch(?![A-Za-z0-9])/, code: "pdf-launch", what: "a /Launch action (starts a program or opens a file)" },
];
const HOLD_KEYS = [
  { re: /\/RichMedia(?![A-Za-z0-9])/, what: "rich media (/RichMedia)" },
  { re: /\/SubmitForm(?![A-Za-z0-9])/, what: "a form that submits to a server (/SubmitForm)" },
  { re: /\/GoToR(?![A-Za-z0-9])/, what: "a link that opens another file (/GoToR)" },
  { re: /\/GoToE(?![A-Za-z0-9])/, what: "a link into an embedded file (/GoToE)" },
  { re: /\/ImportData(?![A-Za-z0-9])/, what: "an action that imports form data (/ImportData)" },
  { re: /\/XFA(?![A-Za-z0-9])/, what: "an XFA form (can carry scripts)" },
];

/**
 * Check 4.
 * @param {import("../index.js").Inspection} ctx
 * @param {Buffer} buf
 * @param {import("../index.js").Node} node
 */
export function checkPdf(ctx, buf, node) {
  if (node.type !== "pdf") return;
  const doc = readPdf(buf, ctx.budget);
  node.pdf = doc;
  const all = `${doc.objects.map((o) => o.dict).join("\n")}\n${doc.trailers}`;

  for (const { re, code, what } of BLOCK_KEYS) {
    const hit = doc.objects.find((o) => re.test(o.dict));
    if (hit) ctx.report("pdf", "block", code, `${what} in object ${hit.num}${hit.inObjectStream ? " (inside an object stream)" : ""}`, node);
  }
  for (const { re, what } of HOLD_KEYS) {
    if (re.test(all)) ctx.report("pdf", "hold", "pdf-active-content", what, node);
  }

  if (doc.encrypted) {
    (node.encryptedParts ??= []).push({ what: "the PDF" });
    return;
  }

  // Embedded files: the streams an /EF dictionary points at, and any
  // stream typed /EmbeddedFile. Named from the file specification.
  const names = new Map();
  for (const o of doc.objects) {
    for (const ef of o.dict.matchAll(/\/EF\s*<<[^>]*?\/(?:UF|F)\s+(\d+)\s+\d+\s+R/g)) {
      names.set(Number(ef[1]), fileSpecName(o.dict) ?? `embedded-${ef[1]}`);
    }
  }
  const byNum = new Map(doc.objects.filter((o) => o.raw).map((o) => [o.num, o]));
  for (const o of doc.objects) {
    if (o.raw && /\/Type\s*\/EmbeddedFile\b/.test(o.dict) && !names.has(o.num)) names.set(o.num, `embedded-${o.num}`);
  }
  for (const [num, name] of names) {
    const o = byNum.get(num);
    if (!o) continue;
    const data = doc.decode(o);
    if (data) ctx.child(node, data, { name, part: `embedded file "${name}"` });
  }

  // Every other stream must decode, or its content is not judged. Images are left encoded on purpose.
  for (const o of doc.objects) {
    if (o.raw && !names.has(o.num)) doc.decode(o);
  }
  for (const problem of doc.unreadable) {
    ctx.report("pdf", "hold", "pdf-unreadable-stream", problem, node);
  }
}

/** The /UF or /F string of a file specification, as plain text. */
function fileSpecName(dict) {
  const m = /\/UF\s*\(((?:\\.|[^\\)])*)\)/.exec(dict) ?? /\/F\s*\(((?:\\.|[^\\)])*)\)/.exec(dict);
  if (!m) return null;
  const raw = m[1].replace(/\\([()\\])/g, "$1");
  const bytes = Buffer.from(raw, "latin1");
  const text = bytes[0] === 0xFE && bytes[1] === 0xFF ? Buffer.from(bytes.subarray(2)).swap16().toString("utf16le") : raw;
  return text.split(/[\\/]/).pop() || null;
}
