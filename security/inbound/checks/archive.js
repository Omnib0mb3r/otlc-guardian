// ============================================================
// OTLC Guardian - inbound-file check 5: archives
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// zip (zip64 included), tar, and gzip as a transparent layer: the
// entries of a.tar.gz are the tar's entries. Every entry is read in
// memory and judged like a file of its own; nothing is extracted.
//
//   - a name that climbs out of its folder (.., an absolute path, a
//     drive letter, a colon) or a link entry blocks: an extractor
//     would write where the sender chose;
//   - an entry that expands more than 100 times (at 1 MiB or more),
//     or a tree over 1 GB uncompressed, blocks as a bomb;
//   - nesting past depth 3, more entries than the limit, a damaged
//     entry, an unsupported compression method, and archive formats
//     with no reader here (7z, rar, bzip2, xz, zstd, cab, disk
//     images) hold.
//
// A zip that is an Office or OpenDocument file is read here too
// (path, bomb and damage rules apply to its parts); its parts go to
// the Office check instead of being listed as entries.
// ============================================================

import { readZip, readZipEntry } from "../readers/zip.js";
import { readTar, gzipName } from "../readers/tar.js";
import { inflateLimited } from "../limits.js";
import { FormatError } from "../errors.js";
import { innerPath, pathProblem } from "../paths.js";
import { detectType } from "./type.js";

export const UNREADABLE_ARCHIVES = new Set(["7z", "rar", "bzip2", "xz", "zstd", "cab", "iso", "vhd", "vhdx"]);
const DOCUMENT_ZIPS = new Set(["ooxml-word", "ooxml-excel", "ooxml-powerpoint", "ooxml", "odf"]);

/**
 * Check 5.
 * @param {import("../index.js").Inspection} ctx
 * @param {Buffer} buf
 * @param {import("../index.js").Node} node
 */
export function checkArchive(ctx, buf, node) {
  if (node.type === "zip") walkZip(ctx, buf, node);
  else if (node.type === "gzip") walkGzip(ctx, buf, node);
  else if (node.type === "tar") walkTar(ctx, buf, node);
  else if (UNREADABLE_ARCHIVES.has(node.type)) {
    ctx.report("archive", "hold", "archive-unreadable",
      `${node.type} has no reader in Guardian; its entries were not checked`, node);
  }
}

const at = (node, name) => ({ path: innerPath(node, name) });

/** False, with a hold, when the node's entries would sit past the depth limit. */
function withinDepth(ctx, node) {
  if (node.depth + 1 <= ctx.budget.limits.depth) return true;
  ctx.report("archive", "hold", "limit-depth",
    `archives nested deeper than ${ctx.budget.limits.depth} levels; the entries were not read`, node);
  return false;
}

/** True, with a block, when `out` bytes from `stored` bytes is a bomb. */
function isBomb(ctx, node, name, stored, out) {
  const { ratio, ratioFloor } = ctx.budget.limits;
  if (out < ratioFloor || out <= ratio * Math.max(1, stored)) return false;
  ctx.report("archive", "block", "archive-bomb-ratio",
    `${name} expands ${Math.round(out / Math.max(1, stored))} times (${stored} to ${out} bytes)`, at(node, name));
  return true;
}

function walkZip(ctx, buf, node) {
  const { entries } = readZip(buf);
  node.type = classifyZip(ctx, buf, entries, node);
  const isDocument = DOCUMENT_ZIPS.has(node.type);
  if (isDocument) node.parts = new Map();
  else if (!withinDepth(ctx, node)) return;
  node.encryptedEntries = [];

  for (const entry of entries) {
    ctx.budget.countEntry();
    const where = isDocument ? node : at(node, entry.name);
    const problem = pathProblem(entry.name);
    if (problem) {
      ctx.report("archive", "block", "archive-path", `entry "${entry.name}" ${problem}`, where);
      continue;
    }
    if (entry.isSymlink) {
      ctx.report("archive", "block", "archive-link", `entry "${entry.name}" is a symbolic link`, where);
      continue;
    }
    if (entry.isDir) continue;
    if (entry.encrypted) {
      node.encryptedEntries.push(entry);
      continue;
    }
    let read;
    try {
      read = readZipEntry(buf, entry, ctx.budget);
    } catch (error) {
      if (!(error instanceof FormatError)) throw error;
      ctx.report("archive", "hold", "archive-unreadable", error.message, where);
      continue;
    }
    if (read.localName !== entry.name) {
      ctx.report("archive", "hold", "archive-name-mismatch",
        `entry "${entry.name}" is named "${read.localName}" in its local header`, where);
    }
    if (!read.crcOk) {
      ctx.report("archive", "hold", "archive-crc", `entry "${entry.name}" does not match its checksum`, where);
      continue;
    }
    if (isBomb(ctx, node, entry.name, entry.compressedSize, read.data.length)) continue;
    if (isDocument) node.parts.set(entry.name, read.data);
    else ctx.child(node, read.data, { name: entry.name, entry: true });
  }
}

/** Refines a zip into the document or package it carries. */
function classifyZip(ctx, buf, entries, node) {
  const names = new Set(entries.map((e) => e.name));
  if (names.has("[Content_Types].xml")) {
    if (names.has("word/document.xml")) return "ooxml-word";
    if (names.has("xl/workbook.xml") || names.has("xl/workbook.bin")) return "ooxml-excel";
    if (names.has("ppt/presentation.xml")) return "ooxml-powerpoint";
    return "ooxml";
  }
  const mimetype = entries.find((e) => e.name === "mimetype" && !e.encrypted && e.size < 200);
  if (mimetype) {
    try {
      if (readZipEntry(buf, mimetype, ctx.budget).data.toString("latin1").startsWith("application/vnd.oasis.opendocument")) return "odf";
    } catch (error) {
      if (!(error instanceof FormatError)) throw error;
    }
  }
  if (names.has("AndroidManifest.xml") && names.has("classes.dex")) return "apk";
  if (names.has("AppxManifest.xml") || names.has("AppxBlockMap.xml")) return "appx";
  if (entries.some((e) => e.name.endsWith(".class")) ||
      (names.has("META-INF/MANIFEST.MF") && /\.jar$/i.test(node.name))) return "jar";
  return "zip";
}

function walkGzip(ctx, buf, node) {
  let data;
  try {
    data = inflateLimited("gzip", buf, ctx.budget);
  } catch (error) {
    if (error?.name === "LimitError") throw error;
    throw new FormatError(`gzip data does not inflate: ${error.message}`);
  }
  if (isBomb(ctx, node, node.name, buf.length, data.length)) return;
  if (detectType(data) === "tar") return walkTar(ctx, data, node);
  if (!withinDepth(ctx, node)) return;
  // The stored name, without any folder: a gzip holds one file.
  const stored = gzipName(buf)?.split(/[\\/]/).pop();
  const name = stored || node.name.replace(/\.tgz$/i, ".tar").replace(/\.gz$/i, "") || "member";
  ctx.child(node, data, { name, entry: true });
}

function walkTar(ctx, buf, node) {
  if (!withinDepth(ctx, node)) return;
  for (const entry of readTar(buf, ctx.budget)) {
    ctx.budget.countEntry();
    const where = at(node, entry.name);
    const problem = pathProblem(entry.name);
    if (problem) {
      ctx.report("archive", "block", "archive-path", `entry "${entry.name}" ${problem}`, where);
      continue;
    }
    if (entry.kind === "symlink" || entry.kind === "hardlink") {
      ctx.report("archive", "block", "archive-link", `entry "${entry.name}" is a ${entry.kind} to "${entry.linkname}"`, where);
      continue;
    }
    if (entry.kind === "special") {
      ctx.report("archive", "block", "archive-special", `entry "${entry.name}" is a device or pipe, not a file`, where);
      continue;
    }
    if (entry.kind === "dir") continue;
    ctx.child(node, entry.data, { name: entry.name, entry: true });
  }
}
