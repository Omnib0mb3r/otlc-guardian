/**
 * ============================================================
 * OTLC GUARDIAN — guardian uninstall tests
 * // tests · onthelevelconcepts.com
 * Version: 1.0.0
 * ============================================================
 *
 * Tests the merge-safety contract of `guardian uninstall`:
 *
 *   - SYMMETRY: a project with custom CLAUDE.md, AGENTS.md, GEMINI.md,
 *     STANDARDS.md, .gitignore, .env.example, and .claude/settings.json
 *     (with non-Guardian hooks) must be byte-for-byte equal to its
 *     original state after `init && uninstall`
 *   - IDEMPOTENCY: running uninstall twice in a row is safe (second
 *     run finds nothing to remove)
 *   - PARTIAL STATE: if the user manually deleted Guardian's marker
 *     from a merged file, uninstall MUST NOT delete the file — it
 *     skips with a warning
 *   - PRE-EXISTING AGENTS.md: a user's AGENTS.md that existed before
 *     guardian init must survive uninstall with its original content
 *   - CUSTOM HOOKS ALONGSIDE GUARDIAN'S: non-Guardian hooks in
 *     .claude/settings.json must NOT be touched
 *   - INVALID SETTINGS.JSON: uninstall refuses to modify malformed
 *     JSON and prints a clear error
 *   - CUSTOM security/ FILES: user-created files in security/ are
 *     preserved; only Guardian's known files are removed
 *   - DRY-RUN: --dry-run prints actions but changes nothing on disk
 *
 * The test harness uses mkdtempSync + subprocess execution so tests
 * never touch real project files. Same mini-runner as init.test.js.
 *
 * Run: node tests/uninstall.test.js
 * ============================================================
 */

import { strict as assert } from "assert";
import { execSync, execFileSync } from "child_process";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  rmSync,
  existsSync,
  statSync,
  readdirSync,
} from "fs";
import { tmpdir } from "os";
import path from "path";
import { fileURLToPath } from "url";
import { createHash } from "crypto";

const __dirname     = path.dirname(fileURLToPath(import.meta.url));
const GUARDIAN_ROOT = path.join(__dirname, "..");
const GUARDIAN_BIN  = path.join(GUARDIAN_ROOT, "bin", "guardian.js");

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

function withTempDir(fn) {
  const dir = mkdtempSync(path.join(tmpdir(), "guardian-uninstall-test-"));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// SUBPROCESS HELPERS — run guardian init / uninstall in a target directory
// ---------------------------------------------------------------------------

function runInit(cwd) {
  return execFileSync("node", [GUARDIAN_BIN, "init"], {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function runUninstall(cwd, ...extraArgs) {
  return execFileSync("node", [GUARDIAN_BIN, "uninstall", ...extraArgs], {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

// Snapshot the contents of a directory as a map of { relPath -> sha256 }.
// Used to assert byte-for-byte equality of an entire project tree before
// and after init/uninstall. Ignores .git and node_modules if present.
function snapshotTree(dir) {
  const out = new Map();
  function walk(current) {
    for (const entry of readdirSync(current)) {
      if (entry === ".git" || entry === "node_modules") continue;
      const full = path.join(current, entry);
      const rel  = path.relative(dir, full).replaceAll("\\", "/");
      const st   = statSync(full);
      if (st.isDirectory()) {
        walk(full);
      } else {
        const content = readFileSync(full);
        const hash = createHash("sha256").update(content).digest("hex");
        out.set(rel, hash);
      }
    }
  }
  walk(dir);
  return out;
}

function diffSnapshots(before, after) {
  const added   = [];
  const removed = [];
  const changed = [];
  for (const [k, v] of after) {
    if (!before.has(k)) added.push(k);
    else if (before.get(k) !== v) changed.push(k);
  }
  for (const k of before.keys()) {
    if (!after.has(k)) removed.push(k);
  }
  return { added, removed, changed };
}

// ---------------------------------------------------------------------------
// SYMMETRY TEST — init + uninstall produces a byte-identical project
// ---------------------------------------------------------------------------

describe("Symmetry — init + uninstall is a no-op on a pre-existing project", () => {
  test("byte-identical round trip on a project with custom content in every managed file", () => {
    withTempDir((dir) => {
      // Set up a project with custom content in every file Guardian
      // knows how to merge. All files end with exactly one trailing
      // newline — this is the conventional form and the one the
      // merge+strip round trip preserves exactly.
      writeFileSync(
        path.join(dir, "CLAUDE.md"),
        "# My project\n\nMy custom CLAUDE rules.\n"
      );
      writeFileSync(
        path.join(dir, "AGENTS.md"),
        "# My agent rules\n\nMy universal agent rules.\n"
      );
      writeFileSync(
        path.join(dir, "GEMINI.md"),
        "# My Gemini rules\n\nMy Gemini-specific rules.\n"
      );
      writeFileSync(
        path.join(dir, "STANDARDS.md"),
        "# My stack\n\nMy team's tech stack.\n"
      );
      writeFileSync(
        path.join(dir, ".gitignore"),
        "node_modules/\ndist/\n.cache/\n"
      );
      writeFileSync(
        path.join(dir, ".env.example"),
        "MY_API_KEY=\nMY_DB_URL=\n"
      );
      // settings.json with a pre-existing non-Guardian hook — tests
      // that Guardian's hooks are added and then removed without
      // touching the user's hook.
      mkdirSync(path.join(dir, ".claude"), { recursive: true });
      const userSettings = {
        model: "opus",
        hooks: {
          PreToolUse: [
            {
              matcher: "Bash",
              hooks: [
                { type: "command", command: "node scripts/pre-bash-check.mjs" },
              ],
            },
          ],
        },
      };
      writeFileSync(
        path.join(dir, ".claude", "settings.json"),
        JSON.stringify(userSettings, null, 2) + "\n"
      );

      const before = snapshotTree(dir);

      runInit(dir);
      runUninstall(dir);

      const after = snapshotTree(dir);
      const diff = diffSnapshots(before, after);

      assert.deepEqual(
        diff.added,
        [],
        `unexpected added files: ${diff.added.join(", ")}`
      );
      assert.deepEqual(
        diff.removed,
        [],
        `unexpected removed files: ${diff.removed.join(", ")}`
      );
      assert.deepEqual(
        diff.changed,
        [],
        `unexpected changed files: ${diff.changed.join(", ")}`
      );
    });
  });
});

// ---------------------------------------------------------------------------
// IDEMPOTENCY — running uninstall twice is safe
// ---------------------------------------------------------------------------

describe("Idempotency — uninstall is safe to re-run", () => {
  test("second uninstall on the same project is a no-op", () => {
    withTempDir((dir) => {
      writeFileSync(
        path.join(dir, "CLAUDE.md"),
        "# My project\n\nMy custom rules.\n"
      );

      runInit(dir);
      runUninstall(dir);
      const after1 = snapshotTree(dir);

      // Second uninstall must not throw and must not change anything.
      runUninstall(dir);
      const after2 = snapshotTree(dir);

      const diff = diffSnapshots(after1, after2);
      assert.deepEqual(diff.added, []);
      assert.deepEqual(diff.removed, []);
      assert.deepEqual(diff.changed, []);
    });
  });
});

// ---------------------------------------------------------------------------
// PARTIAL STATE — user manually deleted Guardian's marker
// ---------------------------------------------------------------------------

describe("Partial state — manual marker removal", () => {
  test("uninstall does NOT delete a merged file whose Guardian marker was manually removed", () => {
    withTempDir((dir) => {
      writeFileSync(
        path.join(dir, "CLAUDE.md"),
        "# My project\n\nMy custom rules.\n"
      );

      runInit(dir);

      // Simulate: user manually edited out the Guardian block, leaving
      // only their original content. The file is now "not Guardian-
      // managed" and uninstall must leave it completely alone.
      writeFileSync(
        path.join(dir, "CLAUDE.md"),
        "# My project\n\nMy (edited) custom rules without any Guardian markers.\n"
      );

      const before = readFileSync(path.join(dir, "CLAUDE.md"), "utf8");
      runUninstall(dir);
      const after = readFileSync(path.join(dir, "CLAUDE.md"), "utf8");

      assert.equal(
        after,
        before,
        "CLAUDE.md without Guardian marker must not be touched by uninstall"
      );
      assert.ok(
        existsSync(path.join(dir, "CLAUDE.md")),
        "uninstall must not delete a file whose marker is absent"
      );
    });
  });
});

// ---------------------------------------------------------------------------
// PRE-EXISTING AGENTS.md — user's Codex setup must survive
// ---------------------------------------------------------------------------

describe("Pre-existing AGENTS.md — Codex user survives init+uninstall", () => {
  test("user's pre-existing AGENTS.md is preserved byte-for-byte across init+uninstall", () => {
    withTempDir((dir) => {
      const userAgents = "# My Codex agent rules\n\nI am a Codex user.\n";
      writeFileSync(path.join(dir, "AGENTS.md"), userAgents);

      runInit(dir);

      // After init the file must still start with user content
      const merged = readFileSync(path.join(dir, "AGENTS.md"), "utf8");
      assert.ok(
        merged.startsWith("# My Codex agent rules"),
        "init must preserve user's AGENTS.md content at the top"
      );

      runUninstall(dir);

      // After uninstall the file must exist and match the original
      assert.ok(
        existsSync(path.join(dir, "AGENTS.md")),
        "uninstall must not delete a pre-existing AGENTS.md"
      );
      const final = readFileSync(path.join(dir, "AGENTS.md"), "utf8");
      assert.equal(
        final,
        userAgents,
        "uninstall must restore AGENTS.md to its pre-init content byte-for-byte"
      );
    });
  });
});

// ---------------------------------------------------------------------------
// CUSTOM HOOKS — non-Guardian hooks must survive uninstall
// ---------------------------------------------------------------------------

describe("Custom hooks — non-Guardian hooks in settings.json are preserved", () => {
  test("user's own hooks are not touched when Guardian's are removed", () => {
    withTempDir((dir) => {
      mkdirSync(path.join(dir, ".claude"), { recursive: true });

      // Two non-Guardian hooks the user added themselves. One shares
      // Guardian's Write|Edit matcher (set-based merge case), one is
      // on a different matcher entirely.
      const userSettings = {
        hooks: {
          PreToolUse: [
            {
              matcher: "Write|Edit",
              hooks: [
                { type: "command", command: "node scripts/pre-write-custom.mjs" },
              ],
            },
            {
              matcher: "Bash",
              hooks: [
                { type: "command", command: "node scripts/pre-bash-custom.mjs" },
              ],
            },
          ],
        },
      };
      const userSettingsSerialized =
        JSON.stringify(userSettings, null, 2) + "\n";
      writeFileSync(
        path.join(dir, ".claude", "settings.json"),
        userSettingsSerialized
      );

      runInit(dir);

      // Confirm Guardian's hooks were added (init correctness sanity)
      const afterInit = JSON.parse(
        readFileSync(path.join(dir, ".claude", "settings.json"), "utf8")
      );
      const writeEditBlock = afterInit.hooks.PreToolUse.find(
        (b) => b.matcher === "Write|Edit"
      );
      assert.ok(
        writeEditBlock.hooks.some(
          (h) => h.command === "node .claude/hooks/injection-guard-hook.mjs"
        ),
        "init must add Guardian's hook to the existing Write|Edit block"
      );
      assert.ok(
        writeEditBlock.hooks.some(
          (h) => h.command === "node scripts/pre-write-custom.mjs"
        ),
        "init must preserve the user's hook in the same block"
      );

      runUninstall(dir);

      const afterUninstall = JSON.parse(
        readFileSync(path.join(dir, ".claude", "settings.json"), "utf8")
      );

      // Guardian's hooks must be gone, user's must remain
      const writeEditBlockAfter = (afterUninstall.hooks?.PreToolUse ?? []).find(
        (b) => b.matcher === "Write|Edit"
      );
      assert.ok(
        writeEditBlockAfter,
        "user's Write|Edit block must still exist"
      );
      assert.ok(
        !writeEditBlockAfter.hooks.some(
          (h) => h.command === "node .claude/hooks/injection-guard-hook.mjs"
        ),
        "Guardian's hook must be removed from the Write|Edit block"
      );
      assert.ok(
        writeEditBlockAfter.hooks.some(
          (h) => h.command === "node scripts/pre-write-custom.mjs"
        ),
        "user's hook must still be in the Write|Edit block"
      );

      const bashBlockAfter = (afterUninstall.hooks?.PreToolUse ?? []).find(
        (b) => b.matcher === "Bash"
      );
      assert.ok(bashBlockAfter, "user's Bash block must still exist");
      assert.ok(
        bashBlockAfter.hooks.some(
          (h) => h.command === "node scripts/pre-bash-custom.mjs"
        ),
        "user's Bash hook must still be present"
      );

      // Guardian's PostToolUse block (WebFetch|WebSearch) must be gone
      // entirely because the user never had any hooks there.
      const postEventArr = afterUninstall.hooks?.PostToolUse ?? [];
      const webBlock = postEventArr.find(
        (b) => b.matcher === "WebFetch|WebSearch"
      );
      assert.ok(
        !webBlock,
        "Guardian's WebFetch|WebSearch matcher block must be gone when empty"
      );
    });
  });
});

// ---------------------------------------------------------------------------
// INVALID SETTINGS.JSON — must refuse to modify
// ---------------------------------------------------------------------------

describe("Invalid settings.json — uninstall refuses to touch it", () => {
  test("uninstall exits non-zero without modifying a malformed settings.json", () => {
    withTempDir((dir) => {
      // Run init first so the "managed file list" is fully populated
      // (so uninstall has something to find even for the other files).
      runInit(dir);

      // Now corrupt the settings.json
      const settingsPath = path.join(dir, ".claude", "settings.json");
      const brokenContent = '{ "hooks": { "PreToolUse": [ { ';
      writeFileSync(settingsPath, brokenContent);

      let threw = false;
      let stderr = "";
      try {
        execFileSync("node", [GUARDIAN_BIN, "uninstall"], {
          cwd: dir,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        });
      } catch (e) {
        threw = true;
        stderr = (e.stderr ?? "") + (e.stdout ?? "");
      }

      assert.ok(threw, "uninstall must exit non-zero when settings.json is invalid");
      assert.ok(
        /INVALID JSON|invalid json|could not be parsed|refusing/i.test(stderr),
        `stderr must mention invalid JSON / refusal — got: ${stderr.slice(0, 200)}`
      );

      // The broken settings.json must still be on disk unchanged
      const afterContent = readFileSync(settingsPath, "utf8");
      assert.equal(
        afterContent,
        brokenContent,
        "uninstall must leave a malformed settings.json untouched"
      );
    });
  });
});

// ---------------------------------------------------------------------------
// CUSTOM security/ FILES — user additions are preserved
// ---------------------------------------------------------------------------

describe("Custom security/ files — user additions preserved", () => {
  test("user-created files in security/ survive uninstall; Guardian's known files are removed", () => {
    withTempDir((dir) => {
      runInit(dir);

      // Simulate: user adds their own rule file in security/
      const customPath = path.join(dir, "security", "my-custom-rules.js");
      const customBody = "// my custom linter rules\nexport const rules = [];\n";
      writeFileSync(customPath, customBody);

      runUninstall(dir);

      // Guardian's files must be gone
      assert.ok(
        !existsSync(path.join(dir, "security", "01-injection-guard.js")),
        "Guardian's 01-injection-guard.js must be removed"
      );
      assert.ok(
        !existsSync(path.join(dir, "security", "03-audit.js")),
        "Guardian's 03-audit.js must be removed"
      );
      assert.ok(
        !existsSync(path.join(dir, "security", "04-sql-guard.js")),
        "Guardian's 04-sql-guard.js must be removed"
      );

      // User's file must still be there, unchanged
      assert.ok(
        existsSync(customPath),
        "user's custom file in security/ must not be deleted"
      );
      assert.equal(
        readFileSync(customPath, "utf8"),
        customBody,
        "user's custom file must not be modified"
      );

      // The security/ directory itself must still exist because it
      // contains a user file. (A v2 could rmdir empty dirs, but v1
      // leaves directories alone.)
      assert.ok(
        existsSync(path.join(dir, "security")),
        "security/ directory must still exist because it has a user file"
      );
    });
  });
});

// ---------------------------------------------------------------------------
// CUSTOMIZED GUARDIAN FILE — user edited Guardian's own file
// ---------------------------------------------------------------------------

describe("Customized Guardian file — skip delete, warn", () => {
  test("a Guardian-copied file that was modified by the user is NOT deleted", () => {
    withTempDir((dir) => {
      runInit(dir);

      // User edits security/03-audit.js to add a custom rule
      const auditPath = path.join(dir, "security", "03-audit.js");
      const original = readFileSync(auditPath, "utf8");
      const modified = original + "\n// user-added comment line\n";
      writeFileSync(auditPath, modified);

      const output = runUninstall(dir);

      assert.ok(
        existsSync(auditPath),
        "a user-modified Guardian file must NOT be deleted"
      );
      assert.equal(
        readFileSync(auditPath, "utf8"),
        modified,
        "a user-modified Guardian file must keep its user modifications"
      );
      assert.ok(
        /modified|customized|skipped|kept/i.test(output),
        `uninstall should warn about the skipped customized file — got: ${output.slice(0, 300)}`
      );
    });
  });
});

// ---------------------------------------------------------------------------
// DRY-RUN — must not modify disk
// ---------------------------------------------------------------------------

describe("Dry run — --dry-run mode does not touch disk", () => {
  test("uninstall --dry-run leaves every file on disk unchanged", () => {
    withTempDir((dir) => {
      writeFileSync(
        path.join(dir, "CLAUDE.md"),
        "# My project\n\nMy custom rules.\n"
      );

      runInit(dir);
      const before = snapshotTree(dir);

      const output = runUninstall(dir, "--dry-run");
      assert.ok(
        /dry[- ]?run|would/i.test(output),
        "dry-run output must say it's a dry run"
      );

      const after = snapshotTree(dir);
      const diff = diffSnapshots(before, after);
      assert.deepEqual(
        diff.added,
        [],
        `dry-run must not add files: ${diff.added.join(", ")}`
      );
      assert.deepEqual(
        diff.removed,
        [],
        `dry-run must not remove files: ${diff.removed.join(", ")}`
      );
      assert.deepEqual(
        diff.changed,
        [],
        `dry-run must not change files: ${diff.changed.join(", ")}`
      );
    });
  });
});

// ---------------------------------------------------------------------------
// ROUTER / HELP — new command must be wired into the CLI router and help
// ---------------------------------------------------------------------------

describe("CLI wiring — uninstall command is visible in help and router", () => {
  test("guardian help mentions uninstall", () => {
    const help = execFileSync("node", [GUARDIAN_BIN, "help"], {
      encoding: "utf8",
    });
    assert.ok(
      /guardian uninstall/.test(help),
      "guardian help must document the uninstall command"
    );
  });

  test("guardian uninstall on a directory with nothing Guardian-managed is a clean no-op", () => {
    withTempDir((dir) => {
      // Empty directory — no Guardian files at all
      writeFileSync(path.join(dir, "README.md"), "# empty project\n");
      const before = snapshotTree(dir);

      const output = runUninstall(dir);

      const after = snapshotTree(dir);
      const diff = diffSnapshots(before, after);
      assert.deepEqual(diff.added, []);
      assert.deepEqual(diff.removed, []);
      assert.deepEqual(diff.changed, []);
      assert.ok(output.length > 0, "uninstall should print something");
    });
  });
});

// ---------------------------------------------------------------------------
// SUMMARY
// ---------------------------------------------------------------------------

console.log(`\n${"=".repeat(60)}`);
console.log(`uninstall tests:  ${passed} passed, ${failed} failed`);
console.log(`${"=".repeat(60)}\n`);

if (failed > 0) {
  console.error("FAILURES:");
  for (const f of failures) {
    console.error(`  • ${f.name}`);
    console.error(`    ${f.error}`);
  }
  process.exit(1);
}
