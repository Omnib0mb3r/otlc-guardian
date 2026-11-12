// ============================================================
// OTLC Guardian - inbound-file check 3: Office documents
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// Office Open XML (.docx, .xlsm and the rest; the archive check has
// already read the parts), OpenDocument, legacy compound files (.doc,
// .xls, .ppt, OLE objects, MSI) and RTF. Nothing is ever run or
// opened by Office.
//
// Block: a VBA project, an Excel 4.0 macro sheet, OpenDocument Basic
// or script macros, a DDE field or formula, a template or OLE object
// fetched from outside the file.
// Hold: other links to outside files (external workbooks, INCLUDE
// fields, linked images), ActiveX controls, embedded OLE packages and
// Equation Editor objects, an RTF object.
// Every embedded file is judged as a file of its own (a program in an
// OLE package blocks). Encrypted documents are recorded for check 6.
// ============================================================

import { readCfb } from "../readers/cfb.js";
import { FormatError } from "../errors.js";
import { decodeXmlEntities } from "../readers/markup.js";

const MSI_CLSIDS = new Set([
  "000c1084-0000-0000-c000-000000000046", // installer
  "000c1086-0000-0000-c000-000000000046", // patch
  "000c1082-0000-0000-c000-000000000046", // transform
]);
const EQUATION_CLSIDS = new Set(["0002ce02-0000-0000-c000-000000000046", "0002ce03-0000-0000-c000-000000000046"]);
const VBA_STORAGES = /^(?:VBA|_VBA_PROJECT_CUR|Macros)$/i;
const OLE_NATIVE = "\u0001Ole10Native";
const DOCUMENT_ZIPS = new Set(["ooxml-word", "ooxml-excel", "ooxml-powerpoint", "ooxml", "odf"]);

/**
 * Check 3.
 * @param {import("../index.js").Inspection} ctx
 * @param {Buffer} buf
 * @param {import("../index.js").Node} node
 */
export function checkOffice(ctx, buf, node) {
  if (DOCUMENT_ZIPS.has(node.type) && node.parts) {
    if (node.type === "odf") inspectOdf(ctx, node);
    else inspectOoxml(ctx, node);
  } else if (node.type === "cfb") {
    inspectCfb(ctx, buf, node);
  } else if (node.type === "rtf") {
    inspectRtf(ctx, buf, node);
  }
}

// ---------------------------------------------------------------------------
// OFFICE OPEN XML
// ---------------------------------------------------------------------------

const attrs = (text) => {
  const out = {};
  for (const m of text.matchAll(/([\w:]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) out[m[1]] = decodeXmlEntities(m[2] ?? m[3]);
  return out;
};
const shortTarget = (t) => (t.length > 120 ? `${t.slice(0, 120)}...` : t);

function inspectOoxml(ctx, node) {
  for (const [name, data] of node.parts) {
    ctx.budget.tick();
    const where = `${name}`;
    if (/(?:^|\/)vbaProject\.bin$/i.test(name)) {
      ctx.report("office", "block", "office-macro", `VBA macro project ${where}`, node);
      continue;
    }
    if (/^xl\/(?:international)?macrosheets\//i.test(name)) {
      ctx.report("office", "block", "office-xlm", `Excel 4.0 macro sheet ${where}`, node);
      continue;
    }
    if (/^(?:word|xl|ppt)\/activeX\//i.test(name)) {
      ctx.report("office", "hold", "office-activex", `ActiveX control ${where}`, node);
      continue;
    }
    if (/^(?:word|xl|ppt)\/embeddings\//i.test(name)) {
      ctx.child(node, data, { name: name.split("/").pop(), part: name });
      continue;
    }
    if (isCfb(data)) {
      // A compound file outside embeddings/ is read for a macro project
      // under any name (a renamed vbaProject.bin).
      ctx.child(node, data, { name: name.split("/").pop(), part: name });
      continue;
    }
    if (name.endsWith(".rels")) {
      inspectRelationships(ctx, node, name, data.toString("utf8"));
      continue;
    }
    if (/^xl\/externalLinks\/[^/]+\.xml$/i.test(name)) {
      const xml = data.toString("utf8");
      if (/<(?:\w+:)?ddeLink\b/.test(xml)) ctx.report("office", "block", "office-dde", `DDE link ${where}`, node);
      else ctx.report("office", "hold", "office-external-link", `link to an external workbook ${where}`, node);
      continue;
    }
    if (name.endsWith(".xml")) inspectFields(ctx, node, name, data.toString("utf8"));
  }
}

function inspectRelationships(ctx, node, name, xml) {
  for (const m of xml.matchAll(/<(?:\w+:)?Relationship\b([^>]*)>/g)) {
    const a = attrs(m[1]);
    if ((a.TargetMode ?? "").toLowerCase() !== "external") continue;
    const type = (a.Type ?? "").split("/").pop().toLowerCase();
    const target = shortTarget(a.Target ?? "");
    if (type === "hyperlink") continue;
    if (type === "attachedtemplate") {
      ctx.report("office", "block", "office-remote-template", `template fetched from ${target} (${name})`, node);
    } else if (["oleobject", "frame", "subdocument", "package"].includes(type)) {
      ctx.report("office", "block", "office-remote-object", `${type} fetched from ${target} (${name})`, node);
    } else {
      ctx.report("office", "hold", "office-external-link", `${type || "relationship"} to ${target} (${name})`, node);
    }
  }
}

/** Field codes in WordprocessingML and formulas in SpreadsheetML. */
function inspectFields(ctx, node, name, xml) {
  // A field's code may be split across runs; a new field starts a new line.
  let codes = "";
  for (const m of xml.matchAll(/<w:fldChar\b[^>]*w:fldCharType="begin"[^>]*>|<w:instrText\b[^>]*>([\s\S]*?)<\/w:instrText>|<w:fldSimple\b([^>]*)>/g)) {
    if (m[1] !== undefined) codes += decodeXmlEntities(m[1]);
    else if (m[2] !== undefined) codes += `\n${attrs(m[2])["w:instr"] ?? ""}\n`;
    else codes += "\n";
  }
  if (/(?:^|[\s"])DDE(?:AUTO)?(?=[\s"]|$)/im.test(codes)) {
    ctx.report("office", "block", "office-dde", `DDE field in ${name}`, node);
  }
  const include = /\b(?:INCLUDEPICTURE|INCLUDETEXT|LINK|IMPORT)\b[^\n]*?(?:https?:|ftp:|file:|\\\\)/i.exec(codes);
  if (include) ctx.report("office", "hold", "office-external-link", `field fetches from outside the file in ${name}`, node);

  for (const m of xml.matchAll(/<(?:\w+:)?f\b[^>]*>([\s\S]*?)<\/(?:\w+:)?f>/g)) {
    // cmd|' /c calc'!A0: a DDE call written as a formula.
    if (/[A-Za-z0-9_.]+\|\s*['"]?[^!]*?['"]?\s*![A-Za-z0-9_$]/.test(decodeXmlEntities(m[1]))) {
      ctx.report("office", "block", "office-dde", `DDE formula in ${name}`, node);
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// OPENDOCUMENT
// ---------------------------------------------------------------------------

function inspectOdf(ctx, node) {
  for (const [name, data] of node.parts) {
    if (/^Basic\/[^/]+\/(?!script-l[bc]\.xml$)[^/]+$/i.test(name) || /^Scripts\/.+[^/]$/i.test(name)) {
      ctx.report("office", "block", "office-macro", `OpenDocument macro ${name}`, node);
    } else if (/^Object \d+\//.test(name) && isCfb(data)) {
      ctx.child(node, data, { name: name.split("/").pop(), part: name });
    }
  }
}

// ---------------------------------------------------------------------------
// COMPOUND FILES
// ---------------------------------------------------------------------------

const isCfb = (b) => b.length >= 8 && b.readUInt32LE(0) === 0xE011CFD0 && b.readUInt32LE(4) === 0xE11AB1A1;
const CONTAINER_MAGIC = [
  (b) => b.length >= 4 && b.readUInt32LE(0) === 0x04034b50,
  isCfb,
  (b) => b.subarray(0, 1024).includes("%PDF-"),
  (b) => b.length >= 2 && b[0] === 0x4D && b[1] === 0x5A,
  (b) => b.length >= 4 && b.readUInt32BE(0) === 0x7F454C46,
];

function inspectCfb(ctx, buf, node) {
  const doc = readCfb(buf, ctx.budget);
  const top = new Set(doc.entries.filter((e) => !e.path.includes("/")).map((e) => e.name));

  if (MSI_CLSIDS.has(doc.root.clsid)) {
    node.type = "msi";
    return;
  }
  if (top.has("EncryptionInfo") && top.has("EncryptedPackage")) {
    node.type = "ooxml-encrypted";
    (node.encryptedParts ??= []).push({ what: "the Office document (password protected)" });
    return;
  }
  if (top.has("WordDocument")) node.type = "cfb-word";
  else if (top.has("Workbook") || top.has("Book")) node.type = "cfb-excel";
  else if (top.has("PowerPoint Document")) node.type = "cfb-powerpoint";

  const vba = doc.entries.find((e) => (e.type === "storage" && VBA_STORAGES.test(e.name)) || e.name === "_VBA_PROJECT");
  if (vba) ctx.report("office", "block", "office-macro", `VBA macro storage ${vba.path}`, node);

  if (EQUATION_CLSIDS.has(doc.root.clsid) || doc.entries.some((e) => EQUATION_CLSIDS.has(e.clsid))) {
    ctx.report("office", "hold", "office-equation", "Equation Editor object (a known exploit route)", node);
  }

  const main = new Set();
  for (const entry of doc.entries) {
    if (entry.type !== "stream") continue;
    ctx.budget.tick();
    if (entry.path === "WordDocument") {
      main.add(entry.path);
      const s = doc.read(entry);
      if (s.length >= 12 && s.readUInt16LE(0) === 0xA5EC && s.readUInt16LE(0x0A) & 0x0100) {
        (node.encryptedParts ??= []).push({ what: "the Word document" });
      }
    } else if (entry.path === "Workbook" || entry.path === "Book") {
      main.add(entry.path);
      inspectBiff(ctx, node, doc.read(entry));
    } else if (entry.path === "EncryptedSummary") {
      (node.encryptedParts ??= []).push({ what: "the PowerPoint presentation" });
    } else if (entry.name === OLE_NATIVE) {
      const pkg = parseOleNative(doc.read(entry));
      ctx.report("office", "hold", "office-embedded-package",
        `embedded OLE package${pkg ? ` "${pkg.name}"` : ""} (${entry.path.replace(OLE_NATIVE, "Ole10Native")})`, node);
      if (pkg) ctx.child(node, pkg.data, { name: pkg.name, part: `package ${pkg.name}` });
    } else {
      const data = doc.read(entry);
      if (CONTAINER_MAGIC.some((test) => test(data))) {
        ctx.child(node, data, { name: entry.name, part: entry.path });
      }
    }
  }
}

/** BIFF8 workbook globals: sheet types and the encryption record. */
function inspectBiff(ctx, node, stream) {
  let p = 0;
  while (p + 4 <= stream.length) {
    const type = stream.readUInt16LE(p);
    const len = stream.readUInt16LE(p + 2);
    const data = stream.subarray(p + 4, p + 4 + len);
    if (type === 0x002F) {
      (node.encryptedParts ??= []).push({ what: "the Excel workbook" });
      return;
    }
    if (type === 0x0085 && data.length >= 8) {
      const sheetType = data[5];
      const nameLen = data[6];
      const wide = data[7] & 1;
      const name = wide ? data.subarray(8, 8 + nameLen * 2).toString("utf16le") : data.subarray(8, 8 + nameLen).toString("latin1");
      if (sheetType === 0x01) ctx.report("office", "block", "office-xlm", `Excel 4.0 macro sheet "${name}"`, node);
      if (sheetType === 0x06) ctx.report("office", "block", "office-macro", `VBA module sheet "${name}"`, node);
    }
    if (type === 0x000A) return; // end of the globals
    p += 4 + len;
  }
}

/** An OLE Package: [size][2][label\0][path\0][3,0][tmp length][tmp][data length][data]. */
function parseOleNative(stream) {
  try {
    let p = 4 + 2;
    const cstr = () => {
      const end = stream.indexOf(0, p);
      if (end < 0) throw new FormatError("unterminated string");
      const s = stream.subarray(p, end).toString("latin1");
      p = end + 1;
      return s;
    };
    const label = cstr();
    cstr();
    p += 4;
    const tempLen = stream.readUInt32LE(p);
    p += 4 + tempLen;
    const size = stream.readUInt32LE(p);
    p += 4;
    if (p + size > stream.length) return null;
    const name = (label || "package").split(/[\\/]/).pop();
    return { name, data: stream.subarray(p, p + size) };
  } catch {
    // A package whose header does not parse is still held as a package;
    // only its payload cannot be judged separately.
    return null;
  }
}

// ---------------------------------------------------------------------------
// RTF
// ---------------------------------------------------------------------------

function inspectRtf(ctx, buf, node) {
  const text = buf.toString("latin1");
  if (/\\object\b|\\objdata\b|\\objemb\b|\\objlink\b|\\objautlink\b/.test(text)) {
    ctx.report("office", "hold", "office-embedded-object", "RTF carries an embedded OLE object", node);
  }
}

export { isCfb };
