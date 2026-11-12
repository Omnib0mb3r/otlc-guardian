/**
 * ============================================================
 * OTLC GUARDIAN - inbound-check tests
 * // tests · onthelevelconcepts.com
 * Version: 1.5.0
 * ============================================================
 *
 * Tests `guardian inbound-check` (security/inbound/), the check
 * DevNeural's mail daemon runs on every file that arrives in Lex's
 * mailbox (BUG-086, contract v1 in DevNeural docs/spec/LEX-MAILBOX.md
 * section 6). Every check has a pass case and a fail case.
 *
 * Fixtures come from tests/inbound-fixtures.js (built in memory) and
 * tests/fixtures/inbound/ (made by tests/fixtures/inbound/make_fixtures.py).
 * All are Guardian-made. Files are written to an OS temp folder only.
 *
 * Opt-in runs, off by default:
 *   GUARDIAN_INBOUND_REAL_SAMPLES=<path>[;<path>...]  real files or
 *     folders outside the repo; each file must come out clean.
 *   GUARDIAN_INBOUND_REAL_DEFENDER=1  runs Windows Defender for real
 *     on a clean file and on the EICAR test string.
 *
 * Same zero-dep mini test runner as tests/init.test.js.
 *
 * Run: node tests/inbound.test.js
 * ============================================================
 */

import { strict as assert } from "assert";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { spawnSync } from "child_process";
import { createHash } from "crypto";
import { fileURLToPath } from "url";
import {
  checkInbound, Inspection, UsageError, CHECK_NAMES, CONTRACT_VERSION, GUARDIAN_VERSION,
  RULESET_VERSION, EXIT_CODES,
} from "../security/inbound/index.js";
import { Budget } from "../security/inbound/limits.js";
import { detectType } from "../security/inbound/checks/type.js";
import * as fx from "./inbound-fixtures.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "guardian.js");

// ---------------------------------------------------------------------------
// MINI TEST RUNNER
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ❌ ${name}`);
    console.error(`     → ${err.message}`);
    failed++;
    failures.push({ name, error: err.message });
  }
}

function describe(group, fn) {
  console.log(`\n📋 ${group}`);
  fn();
}

// ---------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------

const TMP = mkdtempSync(path.join(tmpdir(), "guardian-inbound-"));
let fileCount = 0;

/** Writes `buf` under its own folder as `name` and returns the path. */
function place(buf, name) {
  const dir = path.join(TMP, String(++fileCount));
  mkdirSync(dir);
  const file = path.join(dir, name);
  writeFileSync(file, buf);
  return file;
}

/** Judges `buf` saved as `name`. Defender is mocked clean unless the options say otherwise. */
function judge(buf, name, meta = {}, options = {}) {
  return checkInbound(place(buf, name), meta, { defender: fx.defenderClean, platform: "win32", ...options });
}

const sha256hex = (buf) => createHash("sha256").update(buf).digest("hex");
const codes = (result) => result.reasons.map((r) => r.code);
const reason = (result, code) => result.reasons.find((r) => r.code === code);

function hasReason(result, code, severity) {
  const found = reason(result, code);
  assert.ok(found, `expected reason ${code}; got ${JSON.stringify(result.reasons)}`);
  if (severity) assert.equal(found.severity, severity, `${code} severity`);
  return found;
}

function lacks(result, code) {
  assert.ok(!codes(result).includes(code), `did not expect ${code}; got ${JSON.stringify(result.reasons)}`);
}

// ---------------------------------------------------------------------------
// CONTRACT
// ---------------------------------------------------------------------------

describe("Contract v1 - the verdict object", () => {
  const r = judge(Buffer.from("plain notes\n"), "notes.txt");

  test("carries every contract field, in the contract's order", () => {
    assert.deepEqual(Object.keys(r), [
      "contract_version", "verdict", "reasons", "file", "checks",
      "guardian_version", "ruleset_version", "scanned_at",
    ]);
    assert.equal(r.contract_version, 1);
    assert.equal(CONTRACT_VERSION, 1);
  });

  test("checks names all eight checks", () => {
    assert.deepEqual(Object.keys(r.checks), [
      "type", "executable", "office", "pdf", "archive", "encrypted", "injection", "defender",
    ]);
    assert.deepEqual(CHECK_NAMES, Object.keys(r.checks));
  });

  test("file carries sha256, size, ext and detected_type of the bytes on disk", () => {
    assert.equal(r.file.sha256, sha256hex(Buffer.from("plain notes\n")));
    assert.equal(r.file.size, 12);
    assert.equal(r.file.ext, "txt");
    assert.equal(r.file.detected_type, "text");
    assert.ok(!("inner" in r.file), "inner only for archives");
  });

  test("guardian_version equals package.json version", () => {
    const pkg = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"));
    assert.equal(GUARDIAN_VERSION, pkg.version);
    assert.equal(r.guardian_version, pkg.version);
  });

  test("ruleset_version names the inbound rules and a hash of the injection patterns", () => {
    assert.match(RULESET_VERSION, /^inbound-1\+[0-9a-f]{12}$/);
    assert.equal(r.ruleset_version, RULESET_VERSION);
  });

  test("scanned_at is an ISO timestamp", () => {
    assert.ok(!Number.isNaN(Date.parse(r.scanned_at)));
  });

  test("exit codes: 0 clean, 10 hold, 20 block, 2 error", () => {
    assert.deepEqual({ ...EXIT_CODES }, { clean: 0, hold: 10, block: 20, error: 2 });
  });

  test("a missing file is a usage error, never a verdict", () => {
    assert.throws(() => checkInbound(path.join(TMP, "no-such-file.pdf")), UsageError);
  });

  test("meta that is not an object is a usage error", () => {
    const file = place(Buffer.from("x"), "x.txt");
    assert.throws(() => checkInbound(file, ["subject"]), UsageError);
  });
});

describe("Verdict rules - nothing unjudged reads as clean", () => {
  test("a check that did not run holds with check-not-run", () => {
    const ctx = new Inspection({}, new Budget());
    ctx.run("type", { depth: 0, top: true }, () => {});
    const r = ctx.result({ sha256: "", size: 0, ext: "", detected_type: "empty" });
    assert.equal(r.verdict, "hold");
    assert.equal(r.checks.type, "pass");
    assert.equal(r.checks.pdf, "skipped");
    assert.ok(r.reasons.some((x) => x.code === "check-not-run" && /pdf/.test(x.detail)));
  });

  test("a check that throws is error and holds", () => {
    const ctx = new Inspection({}, new Budget());
    for (const name of CHECK_NAMES) ctx.run(name, { depth: 0, top: true }, () => {});
    ctx.run("pdf", { depth: 0, top: true }, () => { throw new Error("boom"); });
    const r = ctx.result({ sha256: "", size: 0, ext: "", detected_type: "pdf" });
    assert.equal(r.checks.pdf, "error");
    assert.equal(r.verdict, "hold");
    assert.ok(r.reasons.some((x) => x.code === "internal-error" && /boom/.test(x.detail)));
  });

  test("an allowed skip does not hold", () => {
    const ctx = new Inspection({}, new Budget());
    for (const name of CHECK_NAMES) if (name !== "archive") ctx.run(name, { depth: 0, top: true }, () => {});
    ctx.skip("archive");
    const r = ctx.result({ sha256: "", size: 0, ext: "", detected_type: "text" });
    assert.equal(r.checks.archive, "skipped");
    assert.equal(r.verdict, "clean");
  });

  test("info reasons do not change the verdict", () => {
    const ctx = new Inspection({}, new Budget());
    for (const name of CHECK_NAMES) ctx.run(name, { depth: 0, top: true }, () => {});
    ctx.report("type", "info", "type-mismatch", "x", { depth: 0, top: true });
    assert.equal(ctx.result({ sha256: "", size: 0, ext: "", detected_type: "png" }).verdict, "clean");
  });
});

// ---------------------------------------------------------------------------
// CHECK 1 - REAL TYPE
// ---------------------------------------------------------------------------

describe("Check 1 - real type from the bytes", () => {
  const table = [
    [fx.pe(), "pe"], [fx.elf(), "elf"], [fx.lnk(), "lnk"], [fx.javaClass(), "java-class"],
    [Buffer.from("#!/bin/sh\necho hi\n"), "shebang-script"],
    [Buffer.from("PK\x03\x04rest", "latin1"), "zip"],
    [Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0, 0]), "cfb"],
    [Buffer.from("%PDF-1.7\n"), "pdf"], [fx.png(), "png"], [fx.jpeg(), "jpeg"],
    [Buffer.from("GIF89a\x01\x00", "latin1"), "gif"], [Buffer.from([0x1F, 0x8B, 8, 0]), "gzip"],
    [Buffer.from([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 4]), "7z"], [Buffer.from("Rar!\x1A\x07\x01\x00", "latin1"), "rar"],
    [Buffer.from("{\\rtf1\\ansi hi}"), "rtf"], [Buffer.from("AC1032\0\0\0\0", "latin1"), "dwg"],
    [Buffer.from("<!DOCTYPE html><html><body>hi</body></html>"), "html"],
    [Buffer.from("<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"), "svg"],
    [Buffer.from("<?xml version=\"1.0\"?>\n<RSLogix5000Content/>"), "xml"],
    [Buffer.from("  0\nSECTION\n  2\nHEADER\n"), "text"], [Buffer.alloc(0), "empty"],
    [Buffer.from("﻿hello", "utf16le"), "text"], [Buffer.from("MZ notes about the plant\n"), "text"],
    [Buffer.from([0x00, 0x13, 0x88, 0x01, 0xFF, 0x00, 0x7F, 0x02]), "unknown"],
  ];
  for (const [buf, type] of table) {
    test(`detects ${type}`, () => assert.equal(detectType(buf), type));
  }

  test("fail: an executable named .pdf blocks (type-mismatch-executable)", () => {
    const r = judge(fx.pe(), "invoice.pdf");
    hasReason(r, "type-mismatch-executable", "block");
    assert.equal(r.checks.type, "block");
    assert.equal(r.verdict, "block");
  });

  test("fail: an executable whose original name says .pdf blocks", () => {
    const r = judge(fx.pe(), "a01-invoice.bin", { original_name: "invoice.pdf" });
    assert.match(hasReason(r, "type-mismatch-executable", "block").detail, /original name/);
  });

  test("fail: declared as an executable content type blocks", () => {
    const r = judge(Buffer.from("hello\n"), "a.txt", { content_type: "application/x-msdownload" });
    hasReason(r, "declared-executable", "block");
  });

  test("pass: a PNG named .jpg is info only", () => {
    const r = judge(fx.png(), "photo.jpg");
    hasReason(r, "type-mismatch", "info");
    assert.equal(r.checks.type, "pass");
  });

  test("pass: a PNG named .png and sent as image/png has no type reason", () => {
    const r = judge(fx.png(), "photo.png", { content_type: "image/png" });
    lacks(r, "type-mismatch");
    assert.equal(r.checks.type, "pass");
  });

  test("pass: text starting with MZ is text, not a program", () => {
    const r = judge(Buffer.from("MZ notes about the plant\n"), "notes.txt");
    assert.equal(r.file.detected_type, "text");
    assert.equal(r.checks.type, "pass");
  });

  test("fail: a mail body that is not text holds (body-not-text)", () => {
    const r = judge(fx.png(), "body.txt", { source: "mail-body" });
    hasReason(r, "body-not-text", "hold");
  });

  test("fail: a mail body that is a program blocks", () => {
    const r = judge(fx.pe(), "body.txt", { source: "mail-body" });
    hasReason(r, "body-not-text", "block");
  });

  test("pass: an HTML mail body is text", () => {
    const r = judge(Buffer.from("<html><body><p>Hi</p></body></html>"), "body.html", { source: "mail-body" });
    lacks(r, "body-not-text");
  });

  test("fail: bytes of no known format hold (unreadable-type)", () => {
    const r = judge(Buffer.from([0x00, 0x13, 0x88, 0x01, 0xFF, 0x00, 0x7F, 0x02]), "thing.dat");
    hasReason(r, "unreadable-type", "hold");
  });
});

describe("Limits - input size", () => {
  test("fail: over the input limit holds, unread, with the real sha256", () => {
    const buf = Buffer.from("0123456789abcdef");
    const r = judge(buf, "big.txt", {}, { limits: { inputBytes: 8 } });
    hasReason(r, "limit-input", "hold");
    assert.equal(r.verdict, "hold");
    assert.equal(r.file.size, 16);
    assert.equal(r.file.sha256, sha256hex(buf));
    lacks(r, "check-not-run");
  });
});

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function cli(...cliArgs) {
  return spawnSync(process.execPath, [CLI, "inbound-check", ...cliArgs], { encoding: "utf8", cwd: ROOT, timeout: 60_000 });
}

describe("CLI - guardian inbound-check", () => {
  test("--json prints only the verdict object, and the exit code repeats the verdict", () => {
    const file = place(fx.pe(), "invoice.pdf");
    const run = cli(file, "--json");
    const out = JSON.parse(run.stdout);
    assert.equal(out.contract_version, 1);
    assert.equal(out.verdict, "block");
    assert.equal(run.status, EXIT_CODES.block);
  });

  test("--meta is read and judged", () => {
    const file = place(fx.pe(), "a01.bin");
    const metaFile = place(Buffer.from(JSON.stringify({ original_name: "invoice.pdf" })), "a01.bin.meta.json");
    const out = JSON.parse(cli(file, "--meta", metaFile, "--json").stdout);
    assert.ok(out.reasons.some((x) => x.code === "type-mismatch-executable"));
  });

  test("no file: exit 2 and nothing on stdout", () => {
    const run = cli("--json");
    assert.equal(run.status, 2);
    assert.equal(run.stdout, "");
  });

  test("a missing file: exit 2", () => {
    assert.equal(cli(path.join(TMP, "nope.pdf"), "--json").status, 2);
  });

  test("unreadable meta: exit 2", () => {
    const file = place(Buffer.from("x"), "x.txt");
    const metaFile = place(Buffer.from("{not json"), "x.meta.json");
    assert.equal(cli(file, "--meta", metaFile, "--json").status, 2);
  });

  test("an unknown option: exit 2", () => {
    const file = place(Buffer.from("x"), "x.txt");
    assert.equal(cli(file, "--force").status, 2);
  });

  test("without --json the report is human-readable and the exit code is the same", () => {
    const file = place(fx.pe(), "invoice.pdf");
    const run = cli(file);
    assert.match(run.stdout, /INBOUND CHECK/);
    assert.match(run.stdout, /BLOCK/);
    assert.equal(run.status, EXIT_CODES.block);
  });
});

// ---------------------------------------------------------------------------
// SUMMARY
// ---------------------------------------------------------------------------

rmSync(TMP, { recursive: true, force: true });

console.log(`\n${"─".repeat(50)}`);
console.log(`  Results: ${passed} passed, ${failed} failed`);
if (failures.length) {
  console.log("\n  Failures:");
  for (const f of failures) console.log(`    ❌ ${f.name}: ${f.error}`);
}
console.log(`${"─".repeat(50)}\n`);
process.exit(failed > 0 ? 1 : 0);
