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
import { decodeStream } from "../security/inbound/readers/pdf.js";
import zlib from "zlib";
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

// ---------------------------------------------------------------------------
// CHECK 2 - EXECUTABLES AND SCRIPTS
// ---------------------------------------------------------------------------

describe("Check 2 - executables and scripts", () => {
  const programs = [
    [fx.pe(), "setup.exe", "pe"], [fx.elf(), "tool", "elf"], [fx.lnk(), "shortcut.lnk", "lnk"],
    [fx.javaClass(), "Main.class", "java-class"], [Buffer.from("#!/bin/sh\nrm -rf /tmp/x\n"), "run.sh", "shebang-script"],
  ];
  for (const [buf, name, type] of programs) {
    test(`fail: ${type} bytes block (executable)`, () => {
      const r = judge(buf, name);
      assert.match(hasReason(r, "executable", "block").detail, new RegExp(type));
      assert.equal(r.checks.executable, "block");
      assert.equal(r.verdict, "block");
    });
  }

  for (const ext of ["bat", "cmd", "ps1", "vbs", "js", "jse", "wsf", "hta", "scr", "com", "jar", "reg", "url"]) {
    test(`fail: a .${ext} name blocks even when the bytes are text (executable-name)`, () => {
      const r = judge(Buffer.from("echo hello\n"), `tool.${ext}`);
      hasReason(r, "executable-name", "block");
      assert.equal(r.checks.executable, "block");
    });
  }

  test("fail: an original name ending in .exe blocks though the saved name does not", () => {
    const r = judge(Buffer.from("plain text\n"), "a01-report.bin", { original_name: "report.pdf.exe" });
    assert.match(hasReason(r, "executable-name", "block").detail, /original name/);
  });

  test("pass: a text file and a PNG are not executables", () => {
    for (const [buf, name] of [[Buffer.from("notes\n"), "notes.txt"], [fx.png(), "a.png"]]) {
      const r = judge(buf, name);
      assert.equal(r.checks.executable, "pass");
      lacks(r, "executable");
      lacks(r, "executable-name");
    }
  });

  test("pass: a mail body reports the executable check skipped, not held", () => {
    const r = judge(Buffer.from("Hello Michael,\nsee you Tuesday.\n"), "body.txt", { source: "mail-body" });
    assert.equal(r.checks.executable, "skipped");
    assert.ok(!r.reasons.some((x) => x.code === "check-not-run" && /executable/.test(x.detail)));
  });
});

// ---------------------------------------------------------------------------
// CHECK 5 - ARCHIVES
// ---------------------------------------------------------------------------

const L5K_TEXT = "IE_VER := 2.25;\n\nCONTROLLER GuardianTest (ProcessorType := \"1756-L83E\")\n" +
  "\tTAG\n\t\tConveyorRun : BOOL (RADIX := Decimal) := 0;\n\tEND_TAG\nEND_CONTROLLER\n";

describe("Check 5 - archives", () => {
  test("pass: a zip of text, L5K and PNG lists every entry with path, sha256 and size", () => {
    const entries = [
      { name: "readme.txt", data: "Line 3 transfer notes\n" },
      { name: "plc/main.L5K", data: L5K_TEXT },
      { name: "plc/", data: "" },
      { name: "pics/belt.png", data: fx.png(), method: 0 },
    ];
    const r = judge(fx.zip(entries), "job.zip");
    assert.equal(r.checks.archive, "pass", JSON.stringify(r.reasons));
    assert.equal(r.file.detected_type, "zip");
    assert.deepEqual(r.file.inner.map((e) => e.path), ["readme.txt", "plc/main.L5K", "pics/belt.png"]);
    assert.equal(r.file.inner[1].sha256, sha256hex(Buffer.from(L5K_TEXT)));
    assert.equal(r.file.inner[1].size, Buffer.byteLength(L5K_TEXT));
  });

  test("pass: a zip inside a zip lists the inner entries with !/", () => {
    const innerZip = fx.zip([{ name: "a.txt", data: "alpha\n" }]);
    const r = judge(fx.zip([{ name: "docs/inner.zip", data: innerZip }]), "outer.zip");
    assert.deepEqual(r.file.inner.map((e) => e.path), ["docs/inner.zip", "docs/inner.zip!/a.txt"]);
  });

  const slips = ["../../evil.txt", "/etc/x", "C:/x", "a\\..\\..\\evil.txt", "notes.txt:hidden"];
  for (const name of slips) {
    test(`fail: zip slip "${name}" blocks (archive-path)`, () => {
      const r = judge(fx.zip([{ name, data: "x" }]), "slip.zip");
      assert.equal(hasReason(r, "archive-path", "block").path, name);
      assert.equal(r.verdict, "block");
    });
  }

  test("fail: a symbolic link entry blocks (archive-link)", () => {
    const r = judge(fx.zip([{ name: "link", data: "/etc/passwd", symlink: true }]), "link.zip");
    hasReason(r, "archive-link", "block");
  });

  test("fail: a program inside a zip blocks, with the inner path", () => {
    const r = judge(fx.zip([{ name: "tools/setup.exe", data: fx.pe() }]), "tools.zip");
    assert.equal(hasReason(r, "executable", "block").path, "tools/setup.exe");
    assert.equal(r.checks.executable, "block");
  });

  test("fail: a program two archives down blocks, with the nested path", () => {
    const inner = fx.zip([{ name: "x.scr", data: fx.pe() }]);
    const r = judge(fx.zip([{ name: "inner.zip", data: inner }]), "outer.zip");
    assert.equal(hasReason(r, "executable", "block").path, "inner.zip!/x.scr");
  });

  test("fail: 50 MB of zeros in a zip blocks as a bomb (ratio)", () => {
    const r = judge(fx.zip([{ name: "zeros.bin", data: Buffer.alloc(50 * 1024 * 1024) }]), "bomb.zip");
    assert.match(hasReason(r, "archive-bomb-ratio", "block").detail, /expands \d+ times/);
  });

  test("pass: a small file that compresses well is not a bomb (ratio floor)", () => {
    const r = judge(fx.zip([{ name: "spaces.txt", data: " ".repeat(200_000) }]), "spaces.zip");
    lacks(r, "archive-bomb-ratio");
  });

  test("fail: a tree over the uncompressed total blocks (archive-bomb-total)", () => {
    const entries = [1, 2, 3].map((n) => ({ name: `f${n}.txt`, data: `file ${n} `.repeat(400) }));
    const r = judge(fx.zip(entries), "many.zip", {}, { limits: { totalUncompressed: 6000 } });
    hasReason(r, "archive-bomb-total", "block");
    assert.equal(r.verdict, "block");
  });

  test("fail: zips nested past depth 3 hold (limit-depth)", () => {
    let buf = fx.zip([{ name: "deep.txt", data: "bottom\n" }]);
    for (let i = 4; i >= 1; i--) buf = fx.zip([{ name: `level${i}.zip`, data: buf }]);
    const r = judge(buf, "nest.zip");
    hasReason(r, "limit-depth", "hold");
    assert.ok(!r.file.inner.some((e) => e.path.endsWith("deep.txt")), "the deepest entry is not read");
  });

  test("pass: zips nested to depth 3 are read to the bottom", () => {
    let buf = fx.zip([{ name: "deep.txt", data: "bottom\n" }]);
    for (let i = 2; i >= 1; i--) buf = fx.zip([{ name: `level${i}.zip`, data: buf }]);
    const r = judge(buf, "nest.zip");
    lacks(r, "limit-depth");
    assert.ok(r.file.inner.some((e) => e.path === "level1.zip!/level2.zip!/deep.txt"));
  });

  test("fail: more entries than the limit hold (limit-entries)", () => {
    const entries = [1, 2, 3, 4, 5].map((n) => ({ name: `f${n}.txt`, data: "x" }));
    const r = judge(fx.zip(entries), "many.zip", {}, { limits: { entries: 3 } });
    hasReason(r, "limit-entries", "hold");
  });

  test("fail: an unsupported compression method holds (archive-unreadable)", () => {
    const r = judge(fx.zip([{ name: "a.txt", data: "x", method: 12 }]), "bz.zip");
    assert.match(hasReason(r, "archive-unreadable", "hold").detail, /method 12/);
  });

  test("fail: a local name that differs from the central name holds", () => {
    const r = judge(fx.zip([{ name: "invoice.pdf", localName: "invoice.exe", data: "x" }]), "two-names.zip");
    hasReason(r, "archive-name-mismatch", "hold");
  });

  test("fail: an entry that fails its checksum holds (archive-crc)", () => {
    const r = judge(fx.zip([{ name: "a.txt", data: "alpha", crc: 1234 }]), "crc.zip");
    hasReason(r, "archive-crc", "hold");
  });

  test("fail: a truncated zip holds (archive-unreadable)", () => {
    const whole = fx.zip([{ name: "a.txt", data: "alpha" }]);
    const r = judge(whole.subarray(0, whole.length - 30), "cut.zip");
    hasReason(r, "archive-unreadable", "hold");
  });

  for (const [type, bytes] of [
    ["7z", Buffer.from([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 4, 1, 2, 3, 4])],
    ["rar", Buffer.from("Rar!\x1A\x07\x01\x00\x01\x02\x03", "latin1")],
  ]) {
    test(`fail: ${type} has no reader and holds (archive-unreadable)`, () => {
      const r = judge(bytes, `a.${type}`);
      hasReason(r, "archive-unreadable", "hold");
      assert.equal(r.checks.archive, "hold");
    });
  }

  test("pass: a tar lists its files", () => {
    const r = judge(fx.tar([{ name: "a.txt", data: "alpha\n" }, { name: "plc/main.L5K", data: L5K_TEXT }]), "a.tar");
    assert.equal(r.checks.archive, "pass", JSON.stringify(r.reasons));
    assert.deepEqual(r.file.inner.map((e) => e.path), ["a.txt", "plc/main.L5K"]);
  });

  test("fail: tar slip, symlink, hardlink and device entries block", () => {
    const r = judge(fx.tar([
      { name: "../evil.txt", data: "x" },
      { name: "l1", type: "2", linkname: "/etc/passwd" },
      { name: "l2", type: "1", linkname: "/etc/shadow" },
      { name: "dev", type: "3" },
    ]), "bad.tar");
    hasReason(r, "archive-path", "block");
    assert.equal(r.reasons.filter((x) => x.code === "archive-link").length, 2);
    hasReason(r, "archive-special", "block");
  });

  test("pass: a .tar.gz lists the tar's entries directly (gzip is transparent)", () => {
    const r = judge(fx.gzip(fx.tar([{ name: "a.txt", data: "alpha\n" }]), "a.tar"), "a.tar.gz");
    assert.equal(r.file.detected_type, "gzip");
    assert.deepEqual(r.file.inner.map((e) => e.path), ["a.txt"]);
  });

  test("pass: a plain .gz lists its one member under its stored name", () => {
    const r = judge(fx.gzip("hello\n", "notes.txt"), "a01-notes.txt.gz");
    assert.deepEqual(r.file.inner.map((e) => e.path), ["notes.txt"]);
  });

  test("fail: a gzip bomb blocks (ratio)", () => {
    const r = judge(fx.gzip(Buffer.alloc(20 * 1024 * 1024)), "zeros.gz");
    hasReason(r, "archive-bomb-ratio", "block");
  });

  test("pass: a mail body reports the archive check skipped, not held", () => {
    const r = judge(Buffer.from("see attached\n"), "body.txt", { source: "mail-body" });
    assert.equal(r.checks.archive, "skipped");
    assert.ok(!r.reasons.some((x) => x.code === "check-not-run" && /archive/.test(x.detail)));
  });
});

// ---------------------------------------------------------------------------
// CHECK 3 - OFFICE
// ---------------------------------------------------------------------------

const MSI_CLSID = "000c1084-0000-0000-c000-000000000046";
const REL = fx.REL_TYPES;
const relationship = (id, type, target, external = true) =>
  `<Relationship Id="${id}" Type="${REL}/${type}" Target="${target}"${external ? ' TargetMode="External"' : ""}/>`;

describe("Check 3 - Office documents", () => {
  test("pass: a plain .docx is ooxml-word and passes", () => {
    const r = judge(fx.docx(), "notes.docx");
    assert.equal(r.file.detected_type, "ooxml-word");
    assert.equal(r.checks.office, "pass", JSON.stringify(r.reasons));
    assert.ok(!r.file.inner, "a document's parts are not archive entries");
  });

  test("pass: a plain .xlsx with a hyperlink is ooxml-excel and passes", () => {
    const r = judge(fx.xlsx({ parts: [{ name: "xl/worksheets/_rels/sheet1.xml.rels",
      data: `<Relationships>${relationship("rId1", "hyperlink", "https://example.com/")}</Relationships>` }] }), "rates.xlsx");
    assert.equal(r.file.detected_type, "ooxml-excel");
    assert.equal(r.checks.office, "pass", JSON.stringify(r.reasons));
  });

  test("fail: a .docm with a VBA project blocks (office-macro), the macro inert", () => {
    const r = judge(fx.docx({ vba: true }), "report.docm");
    assert.match(hasReason(r, "office-macro", "block").detail, /vbaProject\.bin/);
    assert.equal(r.checks.office, "block");
  });

  test("fail: an .xlsm with a VBA project blocks", () => {
    hasReason(judge(fx.xlsx({ vba: true }), "rates.xlsm"), "office-macro", "block");
  });

  test("fail: an Excel 4.0 macro sheet in an .xlsx blocks (office-xlm)", () => {
    const r = judge(fx.xlsx({ parts: [{ name: "xl/macrosheets/sheet1.xml", data: "<xm:macrosheet/>" }] }), "a.xlsx");
    hasReason(r, "office-xlm", "block");
  });

  test("fail: a remote template (attachedTemplate, external) blocks", () => {
    const r = judge(fx.docx({ settingsRels: relationship("rId1", "attachedTemplate", "https://example.test/t.dotm") }), "a.docx");
    assert.match(hasReason(r, "office-remote-template", "block").detail, /example\.test/);
  });

  test("fail: an external oleObject relationship blocks", () => {
    const r = judge(fx.docx({ rels: relationship("rId9", "oleObject", "mhtml:https://example.test/x!x-usc:https://example.test/x") }), "a.docx");
    hasReason(r, "office-remote-object", "block");
  });

  test("fail: a DDEAUTO field split across runs blocks (office-dde)", () => {
    const body = '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText> DDE</w:instrText></w:r>' +
      '<w:r><w:instrText>AUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc"</w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>';
    hasReason(judge(fx.docx({ body }), "a.docx"), "office-dde", "block");
  });

  test("fail: a DDE formula in a cell blocks", () => {
    const sheet = `<sheetData><row r="1"><c r="A1"><f>cmd|' /C calc'!A0</f></c></row></sheetData>`;
    hasReason(judge(fx.xlsx({ sheet }), "a.xlsx"), "office-dde", "block");
  });

  test("fail: an external workbook link holds (office-external-link)", () => {
    const r = judge(fx.xlsx({ parts: [{ name: "xl/externalLinks/externalLink1.xml", data: "<externalLink><externalBook/></externalLink>" }] }), "a.xlsx");
    hasReason(r, "office-external-link", "hold");
  });

  test("fail: an INCLUDEPICTURE field fetching a URL holds", () => {
    const body = '<w:p><w:fldSimple w:instr=" INCLUDEPICTURE &quot;https://example.test/p.png&quot; \\d "/></w:p>';
    hasReason(judge(fx.docx({ body }), "a.docx"), "office-external-link", "hold");
  });

  test("fail: an ActiveX control holds (office-activex)", () => {
    hasReason(judge(fx.docx({ parts: [{ name: "word/activeX/activeX1.xml", data: "<ax:ocx/>" }] }), "a.docx"), "office-activex", "hold");
  });

  test("fail: an embedded OLE package holding a program holds and the program blocks", () => {
    const r = judge(fx.docx({ parts: [{ name: "word/embeddings/oleObject1.bin", data: fx.olePackage("invoice.exe", fx.pe()) }] }), "a.docx");
    hasReason(r, "office-embedded-package", "hold");
    assert.match(hasReason(r, "executable", "block").detail, /invoice\.exe|pe/);
    assert.equal(r.verdict, "block");
  });

  test("pass: an embedded .xlsx in a .docx is read and passes", () => {
    const r = judge(fx.docx({ parts: [{ name: "word/embeddings/Microsoft_Excel_Worksheet.xlsx", data: fx.xlsx() }] }), "a.docx");
    assert.equal(r.checks.office, "pass", JSON.stringify(r.reasons));
  });

  test("fail: a macro in an .xlsm embedded in a .docx blocks", () => {
    const r = judge(fx.docx({ parts: [{ name: "word/embeddings/x.xlsm", data: fx.xlsx({ vba: true }) }] }), "a.docx");
    hasReason(r, "office-macro", "block");
  });

  test("pass: a legacy .doc with no macros is cfb-word and passes", () => {
    const r = judge(fx.cfb([{ name: "WordDocument", data: fx.wordDocumentStream() }, { name: "1Table", data: Buffer.alloc(5000) }]), "old.doc");
    assert.equal(r.file.detected_type, "cfb-word");
    assert.equal(r.checks.office, "pass", JSON.stringify(r.reasons));
  });

  test("fail: a legacy .doc with a Macros storage blocks", () => {
    const r = judge(fx.cfb([{ name: "WordDocument", data: fx.wordDocumentStream() },
      { name: "Macros", children: [{ name: "VBA", children: [{ name: "dir", data: Buffer.alloc(8) }] }] }]), "old.doc");
    hasReason(r, "office-macro", "block");
  });

  test("fail: a legacy .xls with an Excel 4.0 macro sheet blocks (BOUNDSHEET type 1)", () => {
    const wb = fx.biffWorkbook({ sheets: [{ name: "Sheet1", type: 0 }, { name: "Macro1", type: 1 }] });
    const r = judge(fx.cfb([{ name: "Workbook", data: wb }]), "old.xls");
    assert.equal(r.file.detected_type, "cfb-excel");
    assert.match(hasReason(r, "office-xlm", "block").detail, /Macro1/);
  });

  test("pass: a legacy .xls with plain sheets passes", () => {
    const r = judge(fx.cfb([{ name: "Workbook", data: fx.biffWorkbook() }]), "old.xls");
    assert.equal(r.checks.office, "pass", JSON.stringify(r.reasons));
  });

  test("fail: an encrypted .xls (FILEPASS) holds as encrypted", () => {
    hasReason(judge(fx.cfb([{ name: "Workbook", data: fx.biffWorkbook({ encrypted: true }) }]), "old.xls"), "encrypted", "hold");
  });

  test("fail: an encrypted .doc (FIB flag) holds as encrypted", () => {
    hasReason(judge(fx.cfb([{ name: "WordDocument", data: fx.wordDocumentStream({ encrypted: true }) }]), "old.doc"), "encrypted", "hold");
  });

  test("fail: a password-protected .docx (EncryptedPackage) holds as encrypted", () => {
    const r = judge(fx.cfb([{ name: "EncryptionInfo", data: Buffer.alloc(200) }, { name: "EncryptedPackage", data: Buffer.alloc(5000) }]), "locked.docx");
    assert.equal(r.file.detected_type, "ooxml-encrypted");
    hasReason(r, "encrypted", "hold");
    lacks(r, "type-mismatch");
  });

  test("fail: an MSI installer blocks as a program, even named .doc", () => {
    const r = judge(fx.cfb([{ name: "\u4840\u3f3f", data: Buffer.alloc(10) }], { clsid: MSI_CLSID }), "setup.doc");
    assert.equal(r.file.detected_type, "msi");
    hasReason(r, "executable", "block");
    hasReason(r, "type-mismatch-executable", "block");
  });

  test("fail: a damaged compound file holds (office-unreadable)", () => {
    const good = fx.cfb([{ name: "WordDocument", data: fx.wordDocumentStream() }]);
    const bad = Buffer.from(good);
    bad.writeUInt32LE(0x7FFFFFF0, 48); // directory starts past the end
    hasReason(judge(bad, "bad.doc"), "office-unreadable", "hold");
  });

  test("fail: an RTF carrying an OLE object holds (office-embedded-object)", () => {
    const rtf = "{\\rtf1\\ansi{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata 0105000002000000}}}";
    hasReason(judge(Buffer.from(rtf), "a.rtf"), "office-embedded-object", "hold");
  });

  test("pass: a plain RTF passes", () => {
    const r = judge(Buffer.from("{\\rtf1\\ansi Line 3 transfer notes.\\par}"), "a.rtf");
    assert.equal(r.checks.office, "pass");
  });

  test("fail: OpenDocument with Basic macros blocks", () => {
    const odt = fx.zip([
      { name: "mimetype", data: "application/vnd.oasis.opendocument.text", method: 0 },
      { name: "content.xml", data: "<office:document-content/>" },
      { name: "Basic/Standard/Module1.xml", data: "<script:module/>" },
    ]);
    const r = judge(odt, "a.odt");
    assert.equal(r.file.detected_type, "odf");
    hasReason(r, "office-macro", "block");
  });
});

// ---------------------------------------------------------------------------
// CHECK 4 - PDF
// ---------------------------------------------------------------------------

describe("Check 4 - PDF", () => {
  test("pass: a plain one-page PDF passes", () => {
    const r = judge(fx.pdf(fx.pdfPage()), "notes.pdf");
    assert.equal(r.file.detected_type, "pdf");
    assert.equal(r.checks.pdf, "pass", JSON.stringify(r.reasons));
  });

  test("fail: /OpenAction running JavaScript blocks (inert app.alert)", () => {
    const objs = fx.pdfPage("x", { catalogExtra: "/OpenAction 5 0 R " });
    objs.push("<< /Type /Action /S /JavaScript /JS (app.alert\\('Guardian test'\\);) >>");
    const r = judge(fx.pdf(objs), "a.pdf");
    assert.match(hasReason(r, "pdf-javascript", "block").detail, /object 5/);
    assert.equal(r.verdict, "block");
  });

  test("fail: a /Launch action blocks", () => {
    const objs = fx.pdfPage("x", { catalogExtra: "/OpenAction 5 0 R " });
    objs.push("<< /S /Launch /Win << /F (cmd.exe) >> >>");
    hasReason(judge(fx.pdf(objs), "a.pdf"), "pdf-launch", "block");
  });

  test("fail: a name hidden with #xx escapes (/J#61vaScript) blocks", () => {
    const objs = fx.pdfPage("x", { catalogExtra: "/OpenAction 5 0 R " });
    objs.push("<< /S /J#61vaScript /J#53 (app.alert\\(1\\);) >>");
    hasReason(judge(fx.pdf(objs), "a.pdf"), "pdf-javascript", "block");
  });

  test("fail: JavaScript inside a Flate object stream blocks", () => {
    const objs = fx.pdfPage("x", { catalogExtra: "/OpenAction 6 0 R " });
    objs.push(fx.pdfObjectStream([[6, "<< /S /JavaScript /JS (app.alert\\(1\\);) >>"]]));
    assert.match(hasReason(judge(fx.pdf(objs), "a.pdf"), "pdf-javascript", "block").detail, /object stream/);
  });

  test("fail: JavaScript in an ASCIIHex then Flate object stream blocks", () => {
    const inner = zlib.deflateSync(Buffer.from("6 0 << /S /JavaScript /JS (x) >>\n"));
    const objs = fx.pdfPage("x");
    objs.push({ dict: "/Type /ObjStm /N 1 /First 4 /Filter [/ASCIIHexDecode /FlateDecode]", data: `${inner.toString("hex")}>` });
    hasReason(judge(fx.pdf(objs), "a.pdf"), "pdf-javascript", "block");
  });

  for (const [key, body] of [
    ["SubmitForm", "<< /S /SubmitForm /F (https://example.test/) >>"],
    ["GoToR", "<< /S /GoToR /F (other.pdf) /D [0 /Fit] >>"],
    ["RichMedia", "<< /Type /Annot /Subtype /RichMedia >>"],
  ]) {
    test(`fail: /${key} holds (pdf-active-content)`, () => {
      const objs = fx.pdfPage("x");
      objs.push(body);
      hasReason(judge(fx.pdf(objs), "a.pdf"), "pdf-active-content", "hold");
    });
  }

  test("fail: an encrypted PDF (/Encrypt) holds as encrypted", () => {
    const objs = fx.pdfPage("x");
    objs.push("<< /Filter /Standard /V 2 /R 3 /O (x) /U (y) /P -4 >>");
    hasReason(judge(fx.pdf(objs, { trailer: "/Encrypt 5 0 R " }), "a.pdf"), "encrypted", "hold");
  });

  test("fail: an embedded program blocks, named from its file specification", () => {
    const objs = fx.pdfPage("x", { catalogExtra: "/Names << /EmbeddedFiles << /Names [(invoice) 5 0 R] >> >> " });
    objs.push("<< /Type /Filespec /F (invoice.exe) /UF (invoice.exe) /EF << /F 6 0 R >> >>");
    objs.push({ dict: "/Type /EmbeddedFile", data: fx.pe(), flate: true });
    const r = judge(fx.pdf(objs), "a.pdf");
    hasReason(r, "executable", "block");
    assert.match(hasReason(r, "executable-name", "block").detail, /\.exe/);
  });

  test("pass: an embedded clean text file is read and passes", () => {
    const objs = fx.pdfPage("x");
    objs.push("<< /Type /Filespec /F (notes.txt) /EF << /F 6 0 R >> >>");
    objs.push({ dict: "/Type /EmbeddedFile", data: "plain notes\n", flate: true });
    const r = judge(fx.pdf(objs), "a.pdf");
    assert.equal(r.checks.pdf, "pass", JSON.stringify(r.reasons));
    assert.equal(r.checks.executable, "pass");
  });

  test("fail: a stream with a filter Guardian cannot decode holds", () => {
    const objs = fx.pdfPage("x");
    objs.push({ dict: "/Filter /FooDecode", data: "abc" });
    hasReason(judge(fx.pdf(objs), "a.pdf"), "pdf-unreadable-stream", "hold");
  });

  test("pass: a JPEG image stream is left encoded and passes", () => {
    const objs = fx.pdfPage("x");
    objs.push({ dict: "/Type /XObject /Subtype /Image /Width 1 /Height 1 /Filter /DCTDecode", data: fx.jpeg() });
    assert.equal(judge(fx.pdf(objs), "a.pdf").checks.pdf, "pass");
  });

  test("decoders: LZW (the ISO 32000 example), ASCII85, RunLength", () => {
    const b = new Budget();
    assert.equal(decodeStream("/Filter /LZWDecode", Buffer.from("800B6050220C0C8501", "hex"), b).toString("latin1"), "-----A---B");
    assert.equal(decodeStream("/Filter /ASCII85Decode", Buffer.from("<~87cURD]i,\"Ebo80~>"), b).toString("latin1"), "Hello World!");
    assert.equal(decodeStream("/Filter /RunLengthDecode", Buffer.from([2, 0x61, 0x62, 0x63, 254, 0x7A, 128]), b).toString("latin1"), "abczzz");
  });
});

// ---------------------------------------------------------------------------
// CHECK 6 - ENCRYPTION
// ---------------------------------------------------------------------------

describe("Check 6 - encrypted content holds, never guessed", () => {
  test("fail: a zip entry with the encryption flag (bit 0) holds", () => {
    const r = judge(fx.zip([{ name: "secret.txt", data: "ciphertext", encrypted: true, method: 0 }]), "locked.zip");
    assert.match(hasReason(r, "encrypted", "hold").detail, /secret\.txt/);
    assert.equal(r.checks.encrypted, "hold");
    assert.equal(r.verdict, "hold");
  });

  test("fail: a WinZip AES entry (method 99) holds and says AES", () => {
    const r = judge(fx.zip([{ name: "secret.txt", data: "ciphertext", aes: true }]), "aes.zip");
    assert.match(hasReason(r, "encrypted", "hold").detail, /AES/);
  });

  test("fail: an encrypted entry two archives down holds with the archive's inner path", () => {
    const inner = fx.zip([{ name: "s.txt", data: "x", encrypted: true, method: 0 }]);
    const r = judge(fx.zip([{ name: "in.zip", data: inner }]), "outer.zip");
    assert.equal(hasReason(r, "encrypted", "hold").path, "in.zip");
  });

  test("pass: a plain zip and a text file pass the encryption check", () => {
    for (const [buf, name] of [[fx.zip([{ name: "a.txt", data: "alpha" }]), "a.zip"], [Buffer.from("hi\n"), "a.txt"]]) {
      const r = judge(buf, name);
      assert.equal(r.checks.encrypted, "pass");
      lacks(r, "encrypted");
    }
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
