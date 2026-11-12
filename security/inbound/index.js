// ============================================================
// OTLC Guardian - inbound-file check
// // onthelevelconcepts.com
// Version: 1.5.0
// ============================================================
//
// Judges one file that arrived from outside (Lex's mailbox) before
// anything uses it. Contract v1, agreed with DevNeural in its
// docs/spec/LEX-MAILBOX.md section 6:
//
//   node bin/guardian.js inbound-check <file> [--meta <json>] [--json]
//   exit 0 clean, 10 hold, 20 block, 2 usage or internal error
//
// The file is only read. Archives and documents are walked in
// memory under the limits in limits.js; nothing is extracted to
// disk and nothing is opened by its own application. DevNeural's
// daemon calls the CLI as a child process; checkInbound() is
// exported for Guardian's tests.
//
// Verdict: any block makes block; else any hold (or a check that
// failed or did not run) makes hold; else clean. A check that
// cannot do its job never reads as clean.
// ============================================================

import { readFileSync, statSync, openSync, readSync, closeSync } from "fs";
import { createHash } from "crypto";
import path from "path";
import { INJECTION_PATTERNS } from "../01-injection-guard.js";
import { Budget, LimitError } from "./limits.js";
import { FormatError, UsageError } from "./errors.js";
import { detectType, checkType, extOf } from "./checks/type.js";
import { checkExecutable } from "./checks/executable.js";
import { checkArchive } from "./checks/archive.js";
import { checkEncrypted } from "./checks/encrypted.js";
import { checkOffice } from "./checks/office.js";
import { checkPdf } from "./checks/pdf.js";
import { checkInjection } from "./checks/injection.js";
import { checkAntivirus } from "./checks/antivirus.js";
import { innerPath } from "./paths.js";

export { UsageError };

export const CONTRACT_VERSION = 1;
// Kept equal to package.json by tests/inbound.test.js. A constant, not
// a read of package.json: guardian init copies security/ into other
// projects, where ../../package.json is that project's.
export const GUARDIAN_VERSION = "1.5.0";

export const CHECK_NAMES = Object.freeze([
  "type", "executable", "office", "pdf", "archive", "encrypted", "injection", "antivirus",
]);

export const EXIT_CODES = Object.freeze({ clean: 0, hold: 10, block: 20, error: 2 });

// The inbound rules and the injection rule set they reuse. The suffix
// is a hash of the injection patterns, so a change there gives a new
// ruleset_version without anyone remembering to bump it.
const INBOUND_RULES = "inbound-1";
export const RULESET_VERSION = `${INBOUND_RULES}+${createHash("sha256")
  .update(INJECTION_PATTERNS.map((p) => `${p.id}:${p.severity}:${p.pattern.source}:${p.pattern.flags}`).join("\n"))
  .digest("hex").slice(0, 12)}`;

const META_FIELDS = ["source", "from", "to", "subject", "message_id", "received_at", "original_name", "content_type"];
const DETAIL_MAX = 300;
const SEVERITY_RANK = { info: 0, hold: 1, block: 2 };

/**
 * @typedef {object} Node one thing being judged: the file, an archive
 *   entry, or a part embedded in a document
 * @property {string} name     its own name (entry name, part name)
 * @property {string} [path]   inner archive path, absent for the top-level file and its parts
 * @property {string} [part]   where inside a document it sits, for the reason text
 * @property {number} depth    archive and embedding depth, 0 for the file
 * @property {boolean} top     true for the file itself
 * @property {string} type     real type from the bytes
 */

// ---------------------------------------------------------------------------
// THE WALK
// ---------------------------------------------------------------------------

/** Each step owns one check. Order matters: readers refine `node.type`
 *  before the type check compares names with it. */
const PIPELINE = [
  (ctx, buf, node) => {
    // A mail body is not an archive (contract v1): reported skipped.
    if (ctx.isMailBody && node.top) return ctx.skip("archive");
    ctx.run("archive", node, () => checkArchive(ctx, buf, node));
  },
  (ctx, buf, node) => ctx.run("office", node, () => checkOffice(ctx, buf, node)),
  (ctx, buf, node) => ctx.run("pdf", node, () => checkPdf(ctx, buf, node)),
  // After every reader: what they found locked holds.
  (ctx, buf, node) => ctx.run("encrypted", node, () => checkEncrypted(ctx, node)),
  (ctx, buf, node) => ctx.run("type", node, () => checkType(ctx, node)),
  (ctx, buf, node) => {
    // A mail body is never executed (contract v1): reported skipped.
    if (ctx.isMailBody && node.top) return ctx.skip("executable");
    ctx.run("executable", node, () => checkExecutable(ctx, node));
  },
  // Last: reads the text the readers above found (parts, PDF objects).
  (ctx, buf, node) => ctx.run("injection", node, () => checkInjection(ctx, buf, node)),
];

export class Inspection {
  constructor(meta, budget, options = {}) {
    this.meta = meta;
    this.budget = budget;
    this.options = options;
    this.isMailBody = meta.source === "mail-body";
    this.reasons = [];
    this.inner = [];
    // What scanned the file in the antivirus check; null when nothing did.
    this.antivirusEngine = null;
    this.stopped = false;
    this.state = Object.fromEntries(CHECK_NAMES.map((name) => [name, { ran: false, error: false, allowedSkip: false, why: null }]));
  }

  /** Records a finding. `info` explains and changes nothing. */
  report(check, severity, code, detail, node) {
    const reason = { code, severity, detail: clip(detail) };
    if (node?.path !== undefined) reason.path = node.path;
    else if (node?.metaField) reason.path = node.metaField;
    const duplicate = this.reasons.some((r) =>
      r.code === reason.code && r.path === reason.path && r.detail === reason.detail);
    if (!duplicate) this.reasons.push({ ...reason, check });
  }

  /** A check that does not apply here and must not count against clean. */
  skip(check) {
    this.state[check].allowedSkip = true;
  }

  /** A check that cannot run here. It is reported skipped, and that holds, with `why`. */
  notRun(check, why) {
    this.state[check].why = why;
  }

  /**
   * Runs one check on one node. Malformed bytes hold under that check;
   * any other failure marks the check `error`, which holds. A limit
   * stops the whole walk.
   */
  run(check, node, fn) {
    this.state[check].ran = true;
    try {
      fn();
    } catch (error) {
      if (error instanceof LimitError) {
        if (!error.recorded) {
          this.report(check, error.severity, error.code, error.message, node);
          error.recorded = true;
        }
        throw error;
      }
      if (error instanceof FormatError) {
        this.report(check, "hold", `${check}-unreadable`, error.message, node);
        return;
      }
      this.state[check].error = true;
      this.report(check, "hold", "internal-error", `${check} check failed: ${error?.message ?? error}`, node);
    }
  }

  /** Lists an archive entry in `file.inner`. */
  addInner(node, buf) {
    this.inner.push({ path: node.path, sha256: sha256(buf), size: buf.length });
  }

  inspect(buf, node) {
    this.budget.tick();
    node.type = detectType(buf);
    for (const step of PIPELINE) step(this, buf, node);
  }

  /**
   * Inspects something found inside `parent`. An archive entry gets
   * its own inner path; a part embedded in a document keeps its
   * container's path and is named in `part`. Past the depth limit the
   * child is not read, and the parent holds.
   */
  child(parent, buf, { name, entry = false, part }) {
    const node = {
      name,
      depth: parent.depth + 1,
      top: false,
      type: "unknown",
      path: entry ? innerPath(parent, name) : parent.path,
      part: entry ? undefined : [parent.part, part ?? name].filter(Boolean).join(" > "),
    };
    if (node.depth > this.budget.limits.depth) {
      this.report("archive", "hold", "limit-depth",
        `nested deeper than ${this.budget.limits.depth} levels; ${node.part || name} was not read`, parent);
      return node;
    }
    if (entry) this.addInner(node, buf);
    this.inspect(buf, node);
    return node;
  }

  /** Walks the file. A limit ends the walk; what was found so far stands. */
  walk(buf, root) {
    try {
      this.inspect(buf, root);
    } catch (error) {
      if (!(error instanceof LimitError)) throw error;
      this.stopped = true;
    }
  }

  result(file) {
    const checks = {};
    for (const name of CHECK_NAMES) {
      const own = this.reasons.filter((r) => r.check === name);
      const worst = own.reduce((max, r) => Math.max(max, SEVERITY_RANK[r.severity]), 0);
      const st = this.state[name];
      checks[name] = worst === 2 ? "block" : st.error ? "error" : worst === 1 ? "hold" : st.ran ? "pass" : "skipped";
      // A check that should have run and did not is never clean. When a
      // limit stopped the walk, that limit is already the reason.
      if (checks[name] === "skipped" && !st.allowedSkip && (st.why || !this.stopped)) {
        this.report(name, "hold", "check-not-run", st.why ?? `the ${name} check did not run`);
      }
    }
    const worst = this.reasons.reduce((max, r) => Math.max(max, SEVERITY_RANK[r.severity]), 0);
    const verdict = worst === 2 ? "block" : worst === 1 ? "hold" : "clean";
    const outFile = { ...file };
    if (this.inner.length) outFile.inner = this.inner;
    return {
      contract_version: CONTRACT_VERSION,
      verdict,
      reasons: this.reasons.map(({ check: _check, ...reason }) => reason),
      file: outFile,
      checks,
      antivirus_engine: this.antivirusEngine,
      guardian_version: GUARDIAN_VERSION,
      ruleset_version: RULESET_VERSION,
      scanned_at: new Date(this.options.now ? this.options.now() : Date.now()).toISOString(),
    };
  }
}

// ---------------------------------------------------------------------------
// ENTRY POINT
// ---------------------------------------------------------------------------

/**
 * Judges one file.
 *
 * @param {string} filePath
 * @param {object} [meta] untrusted mail metadata: source, from, to, subject,
 *   message_id, received_at, original_name, content_type
 * @param {object} [options] for tests: `limits`, `now`, `platform`, and `antivirus`,
 *   a runner `(path, timeoutMs, name) => { engine, status, detail }` in place of the
 *   machine's antivirus
 * @returns {object} the contract v1 verdict object
 * @throws {UsageError} when the path is not a readable file
 */
export function checkInbound(filePath, meta = {}, options = {}) {
  if (typeof filePath !== "string" || filePath === "") throw new UsageError("a file path is required");
  let stat;
  try {
    stat = statSync(filePath);
  } catch (error) {
    throw new UsageError(`cannot read ${filePath}: ${error.code ?? error.message}`);
  }
  if (!stat.isFile()) throw new UsageError(`${filePath} is not a file`);

  const budget = new Budget(options.limits, options.now);
  const ctx = new Inspection(normalizeMeta(meta), budget, options);
  const root = { name: path.basename(filePath), depth: 0, top: true, type: "unknown" };

  let digest;
  let buf = null;
  try {
    if (stat.size > budget.limits.inputBytes) {
      digest = hashFile(filePath);
      root.type = detectType(readHead(filePath, 64 * 1024));
    } else {
      buf = readFileSync(filePath);
      digest = sha256(buf);
    }
  } catch (error) {
    // The file is there and cannot be opened: locked, no permission, or
    // held back by an antivirus (Windows refuses to open a file its
    // real-time protection has flagged). Not a verdict: exit 2, which
    // the daemon holds.
    throw new UsageError(`cannot read ${filePath}: ${error.code ?? error.message}`);
  }
  if (buf === null) {
    ctx.report("type", "hold", "limit-input",
      `${stat.size} bytes is over the ${budget.limits.inputBytes} byte limit; the contents were not read`);
    ctx.stopped = true;
  } else {
    ctx.walk(buf, root);
  }

  // The antivirus scans the file on disk, once, whatever the walk found:
  // a file too big to read here is still scanned.
  if ((options.platform ?? process.platform) === "win32") {
    ctx.run("antivirus", root, () => checkAntivirus(ctx, filePath, root));
  } else {
    ctx.notRun("antivirus", "the antivirus check runs only on Windows (Windows Defender or an AMSI provider); the file was not scanned for malware");
  }

  return ctx.result({ sha256: digest, size: stat.size, ext: extOf(root.name), detected_type: root.type });
}

/** Keeps the known meta fields that are strings. Everything in meta is untrusted text. */
function normalizeMeta(meta) {
  if (meta === null || meta === undefined) return {};
  if (typeof meta !== "object" || Array.isArray(meta)) throw new UsageError("meta must be a JSON object");
  const out = {};
  for (const field of META_FIELDS) {
    if (typeof meta[field] === "string") out[field] = meta[field];
  }
  return out;
}

function clip(text) {
  const s = String(text);
  return s.length > DETAIL_MAX ? `${s.slice(0, DETAIL_MAX)}...` : s;
}

function sha256(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function hashFile(filePath) {
  const hash = createHash("sha256");
  const chunk = Buffer.allocUnsafe(1024 * 1024);
  const fd = openSync(filePath, "r");
  try {
    let n;
    while ((n = readSync(fd, chunk, 0, chunk.length, null)) > 0) hash.update(chunk.subarray(0, n));
  } finally {
    closeSync(fd);
  }
  return hash.digest("hex");
}

function readHead(filePath, bytes) {
  const buf = Buffer.alloc(bytes);
  const fd = openSync(filePath, "r");
  try {
    return buf.subarray(0, readSync(fd, buf, 0, bytes, 0));
  } finally {
    closeSync(fd);
  }
}
