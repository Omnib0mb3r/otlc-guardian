// ============================================================
// OTLC Guardian - inbound-file check 1: real type
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// The type of a file is what its bytes say, never its name. The
// name (on disk and as sent) and the declared content type are
// compared with it afterwards:
//
//   - a mismatch that hides an executable or a script blocks;
//   - any other mismatch is reported as info and changes nothing;
//   - a mail body that is not text holds;
//   - bytes of no known format hold: what is not read is not
//     judged, so it is never clean. Archives Guardian cannot open
//     are held by the archive check.
//
// CAD model files (STEP, IGES, STL) have no magic number; they are
// known by their structure (readers/cad.js). DWG is known by its
// version tag, and an ASCII DXF is plain text.
// ============================================================

import { decodeText } from "../readers/text.js";
import { cadTextType, isBinaryStl } from "../readers/cad.js";

const at = (buf, offset, bytes) =>
  buf.length >= offset + bytes.length && bytes.every((b, i) => buf[offset + i] === b);
const ascii = (buf, offset, text) => at(buf, offset, [...text].map((ch) => ch.charCodeAt(0)));

export const FAMILY = Object.freeze({
  pe: "executable", "dos-exe": "executable", elf: "executable", macho: "executable",
  "java-class": "executable", lnk: "executable", "shebang-script": "executable",
  wasm: "executable", dex: "executable", chm: "executable", msi: "executable",
  jar: "executable", apk: "executable", appx: "executable",

  zip: "archive", gzip: "archive", tar: "archive", "7z": "archive", rar: "archive",
  bzip2: "archive", xz: "archive", zstd: "archive", cab: "archive", iso: "archive",
  vhd: "archive", vhdx: "archive",

  "ooxml-word": "office", "ooxml-excel": "office", "ooxml-powerpoint": "office",
  ooxml: "office", "ooxml-encrypted": "office", odf: "office",
  cfb: "office", "cfb-word": "office", "cfb-excel": "office", "cfb-powerpoint": "office",
  rtf: "office",

  pdf: "pdf",
  png: "image", jpeg: "image", gif: "image", webp: "image", bmp: "image",
  tiff: "image", ico: "image", heic: "image",
  mp4: "media", mp3: "media", wav: "media", avi: "media", ogg: "media", flac: "media",
  dwg: "cad", "dxf-binary": "cad", "stl-binary": "cad",
  text: "text", html: "text", svg: "text", xml: "text",
  // Text built as a CAD exchange file. Read as text like any other.
  step: "text", iges: "text", "stl-ascii": "text",
  empty: "empty", unknown: "unknown",
});

/**
 * Real type from the bytes. Containers are refined later by their
 * readers (a zip becomes ooxml-word, jar and so on; a compound file
 * becomes cfb-excel or msi).
 *
 * @param {Buffer} buf
 * @returns {string}
 */
export function detectType(buf) {
  if (buf.length === 0) return "empty";
  if (ascii(buf, 0, "MZ")) {
    const peOffset = buf.length >= 0x40 ? buf.readUInt32LE(0x3C) : -1;
    if (peOffset > 0 && ascii(buf, peOffset, "PE\0\0")) return "pe";
    // "MZ" with no PE header: a DOS program, unless the bytes are text
    // that merely starts with those two letters.
    return decodeText(buf.subarray(0, 4096)) ? textType(buf) : "dos-exe";
  }
  if (at(buf, 0, [0x7F, 0x45, 0x4C, 0x46])) return "elf";
  if (at(buf, 0, [0xFE, 0xED, 0xFA, 0xCE]) || at(buf, 0, [0xFE, 0xED, 0xFA, 0xCF]) ||
      at(buf, 0, [0xCE, 0xFA, 0xED, 0xFE]) || at(buf, 0, [0xCF, 0xFA, 0xED, 0xFE])) return "macho";
  if (at(buf, 0, [0xCA, 0xFE, 0xBA, 0xBE])) {
    // Shared by a Mach-O universal binary (a small architecture count
    // follows) and a Java class file (a version number follows).
    return buf.length >= 8 && buf.readUInt32BE(4) < 32 ? "macho" : "java-class";
  }
  if (at(buf, 0, [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])) return "lnk";
  if (ascii(buf, 0, "#!")) return "shebang-script";
  if (at(buf, 0, [0x00, 0x61, 0x73, 0x6D])) return "wasm";
  if (ascii(buf, 0, "dex\n")) return "dex";
  if (ascii(buf, 0, "ITSF")) return "chm";

  if (ascii(buf, 0, "PK\x03\x04") || ascii(buf, 0, "PK\x05\x06") || ascii(buf, 0, "PK\x07\x08")) return "zip";
  if (at(buf, 0, [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])) return "cfb";
  if (buf.subarray(0, 1024).includes("%PDF-")) return "pdf";

  if (at(buf, 0, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])) return "png";
  if (at(buf, 0, [0xFF, 0xD8, 0xFF])) return "jpeg";
  if (ascii(buf, 0, "GIF87a") || ascii(buf, 0, "GIF89a")) return "gif";
  if (ascii(buf, 0, "RIFF") && ascii(buf, 8, "WEBP")) return "webp";
  if (ascii(buf, 0, "RIFF") && ascii(buf, 8, "WAVE")) return "wav";
  if (ascii(buf, 0, "RIFF") && ascii(buf, 8, "AVI ")) return "avi";
  if (ascii(buf, 0, "BM") && buf.length >= 6 && buf.readUInt32LE(2) === buf.length) return "bmp";
  if (ascii(buf, 0, "II*\0") || ascii(buf, 0, "MM\0*")) return "tiff";
  if (at(buf, 0, [0x00, 0x00, 0x01, 0x00]) && buf.length >= 6 && buf.readUInt16LE(4) > 0 && buf.readUInt16LE(4) <= 64) return "ico";
  if (ascii(buf, 4, "ftyp")) {
    const brand = buf.subarray(8, 12).toString("latin1");
    return ["heic", "heix", "mif1", "msf1", "avif"].includes(brand) ? "heic" : "mp4";
  }
  if (ascii(buf, 0, "ID3") || at(buf, 0, [0xFF, 0xFB]) || at(buf, 0, [0xFF, 0xF3]) || at(buf, 0, [0xFF, 0xF2])) return "mp3";
  if (ascii(buf, 0, "OggS")) return "ogg";
  if (ascii(buf, 0, "fLaC")) return "flac";

  if (at(buf, 0, [0x1F, 0x8B])) return "gzip";
  if (ascii(buf, 257, "ustar")) return "tar";
  if (at(buf, 0, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])) return "7z";
  if (ascii(buf, 0, "Rar!\x1A\x07")) return "rar";
  if (ascii(buf, 0, "BZh") && buf[3] >= 0x31 && buf[3] <= 0x39) return "bzip2";
  if (at(buf, 0, [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00])) return "xz";
  if (at(buf, 0, [0x28, 0xB5, 0x2F, 0xFD])) return "zstd";
  if (ascii(buf, 0, "MSCF")) return "cab";
  if (ascii(buf, 0x8001, "CD001") || ascii(buf, 0x8801, "CD001") || ascii(buf, 0x9001, "CD001")) return "iso";
  if (ascii(buf, 0, "conectix")) return "vhd";
  if (ascii(buf, 0, "vhdxfile")) return "vhdx";

  if (ascii(buf, 0, "{\\rtf")) return "rtf";
  if (/^AC1\d{3}/.test(buf.subarray(0, 6).toString("latin1"))) return "dwg";
  if (ascii(buf, 0, "AutoCAD Binary DXF")) return "dxf-binary";

  const decoded = decodeText(buf);
  if (decoded) return cadTextType(decoded.text) ?? textType(buf);
  return isBinaryStl(buf) ? "stl-binary" : "unknown";
}

/** Types whose bytes are plain text, read whole by the prompt-injection check. */
export const PLAIN_TEXT_TYPES = new Set(["text", "step", "iges", "stl-ascii"]);

/** Splits text into plain text, HTML, SVG and other XML by its opening. */
function textType(buf) {
  const head = (decodeText(buf.subarray(0, 4096))?.text ?? "").replace(/^﻿/, "").trimStart().toLowerCase();
  const afterProlog = head.replace(/^(?:<\?xml[^>]*\?>|<!--[\s\S]*?-->|\s)+/, "");
  if (/^<svg[\s>]/.test(afterProlog) || /^<!doctype svg/.test(afterProlog)) return "svg";
  if (/^<!doctype html|^<html[\s>]|^<head[\s>]|^<body[\s>]/.test(afterProlog)) return "html";
  if (/^<(?:meta|div|table|p|span|br|style|title|a|font|center|h[1-6])[\s>/]/.test(afterProlog)) return "html";
  if (head.startsWith("<?xml") || /^<[a-z_][\w:.-]*[\s>/]/.test(afterProlog)) return "xml";
  return "text";
}

// ---------------------------------------------------------------------------
// NAMES AND DECLARED TYPES
// ---------------------------------------------------------------------------

const TEXT_LIKE = ["text", "xml", "html", "svg"];
const OOXML_WORD  = ["ooxml-word", "ooxml-encrypted"];
const OOXML_EXCEL = ["ooxml-excel", "ooxml-encrypted"];
const OOXML_PPT   = ["ooxml-powerpoint", "ooxml-encrypted"];

/** What each extension's bytes may be. An extension not listed is not judged. */
const EXPECTED = {
  pdf: ["pdf"], png: ["png"], jpg: ["jpeg"], jpeg: ["jpeg"], jpe: ["jpeg"], jfif: ["jpeg"],
  gif: ["gif"], webp: ["webp"], bmp: ["bmp"], tif: ["tiff"], tiff: ["tiff"], ico: ["ico"],
  heic: ["heic"], heif: ["heic"], avif: ["heic"],
  zip: ["zip"], gz: ["gzip"], tgz: ["gzip"], tar: ["tar"], "7z": ["7z"], rar: ["rar"],
  bz2: ["bzip2"], xz: ["xz"], zst: ["zstd"], cab: ["cab"], iso: ["iso"], vhd: ["vhd"], vhdx: ["vhdx"],
  docx: OOXML_WORD, docm: OOXML_WORD, dotx: OOXML_WORD, dotm: OOXML_WORD,
  xlsx: OOXML_EXCEL, xlsm: OOXML_EXCEL, xltx: OOXML_EXCEL, xltm: OOXML_EXCEL, xlam: OOXML_EXCEL, xlsb: OOXML_EXCEL,
  pptx: OOXML_PPT, pptm: OOXML_PPT, potx: OOXML_PPT, ppsx: OOXML_PPT, ppsm: OOXML_PPT,
  odt: ["odf"], ods: ["odf"], odp: ["odf"],
  doc: ["cfb-word"], dot: ["cfb-word"], xls: ["cfb-excel"], xlt: ["cfb-excel"],
  ppt: ["cfb-powerpoint"], pps: ["cfb-powerpoint"], rtf: ["rtf"],
  txt: TEXT_LIKE, text: TEXT_LIKE, log: TEXT_LIKE, csv: TEXT_LIKE, tsv: TEXT_LIKE, md: TEXT_LIKE,
  json: TEXT_LIKE, yaml: TEXT_LIKE, yml: TEXT_LIKE, ini: TEXT_LIKE, cfg: TEXT_LIKE,
  l5k: TEXT_LIKE, step: ["step"], stp: ["step"], igs: ["iges"], iges: ["iges"],
  stl: ["stl-ascii", "stl-binary"],
  dxf: [...TEXT_LIKE, "dxf-binary"],
  xml: ["xml", "svg", "html"], l5x: ["xml"], svg: ["svg", "xml"],
  html: ["html", "xml", "text"], htm: ["html", "xml", "text"],
  dwg: ["dwg"], mp4: ["mp4"], m4a: ["mp4"], mov: ["mp4"], mp3: ["mp3"], wav: ["wav"],
  avi: ["avi"], ogg: ["ogg"], flac: ["flac"],
  // .scr is a Windows screensaver (a program) and also an AutoCAD script (plain text).
  exe: ["pe", "dos-exe"], dll: ["pe"], sys: ["pe"], scr: ["pe", "text"], cpl: ["pe"], ocx: ["pe"],
  com: ["dos-exe", "pe"], msi: ["msi"], msp: ["msi"], lnk: ["lnk"], jar: ["jar"],
  class: ["java-class"], apk: ["apk"], appx: ["appx"], msix: ["appx"], chm: ["chm"],
};

const DECLARED_EXECUTABLE = new Set([
  "application/x-msdownload", "application/x-dosexec", "application/x-msdos-program",
  "application/vnd.microsoft.portable-executable", "application/x-executable",
  "application/x-sh", "application/x-csh", "application/x-shellscript",
  "application/javascript", "application/x-javascript", "text/javascript", "text/vbscript",
  "application/x-bat", "application/bat", "application/x-msi", "application/x-ms-installer",
  "application/hta", "application/x-ms-shortcut", "application/java-archive",
  "application/vnd.android.package-archive", "application/x-powershell",
]);

/** Broad family a declared MIME type stands for, or null when it says nothing. */
function declaredFamily(contentType) {
  const mime = contentType.split(";")[0].trim().toLowerCase();
  if (!mime || mime === "application/octet-stream") return null;
  if (DECLARED_EXECUTABLE.has(mime)) return "executable";
  if (mime === "application/pdf") return "pdf";
  if (mime.startsWith("image/")) return "image";
  if (mime.startsWith("audio/") || mime.startsWith("video/")) return "media";
  if (mime.startsWith("text/") || mime.endsWith("+xml") || mime === "application/xml" || mime === "application/json") return "text";
  if (/zip|x-tar|gzip|x-7z|rar|bzip|x-xz/.test(mime)) return "archive";
  if (/officedocument|msword|ms-excel|ms-powerpoint|opendocument|ms-office|rtf/.test(mime)) return "office";
  return null;
}

export const extOf = (name) => {
  const base = String(name ?? "").split(/[\\/]/).pop();
  const dot = base.lastIndexOf(".");
  return dot > 0 ? base.slice(dot + 1).toLowerCase() : "";
};

/**
 * Check 1. Runs after the readers have refined the node's type.
 * @param {import("../index.js").Inspection} ctx
 * @param {import("../index.js").Node} node
 */
export function checkType(ctx, node) {
  const names = [{ name: node.name, label: "name" }];
  if (node.top && ctx.meta.original_name && extOf(ctx.meta.original_name) !== extOf(node.name)) {
    names.push({ name: ctx.meta.original_name, label: "original name" });
  }
  for (const { name, label } of names) {
    const ext = extOf(name);
    const expected = EXPECTED[ext];
    if (!expected || expected.includes(node.type)) continue;
    if (FAMILY[node.type] === "executable") {
      ctx.report("type", "block", "type-mismatch-executable",
        `${label} ends in .${ext} but the bytes are ${node.type}`, node);
    } else {
      ctx.report("type", "info", "type-mismatch", `${label} ends in .${ext} but the bytes are ${node.type}`, node);
    }
  }

  if (node.top && ctx.meta.content_type) {
    const declared = declaredFamily(ctx.meta.content_type);
    if (declared === "executable") {
      ctx.report("type", "block", "declared-executable", `sent as ${ctx.meta.content_type.slice(0, 100)}`, node);
    } else if (declared && declared !== FAMILY[node.type] && FAMILY[node.type] !== "empty") {
      ctx.report("type", "info", "type-mismatch",
        `sent as ${ctx.meta.content_type.slice(0, 100)} but the bytes are ${node.type}`, node);
    }
  }

  if (node.top && ctx.isMailBody && !["text", "empty"].includes(FAMILY[node.type])) {
    ctx.report("type", FAMILY[node.type] === "executable" ? "block" : "hold", "body-not-text",
      `a mail body must be text or HTML; the bytes are ${node.type}`, node);
  }

  // Archives Guardian cannot open (7z, rar and the like) are held by
  // the archive check; here, bytes of no known format.
  if (node.type === "unknown") {
    ctx.report("type", "hold", "unreadable-type", "format not recognised; its contents were not read", node);
  }
}
