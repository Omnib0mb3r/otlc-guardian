/**
 * ============================================================
 * OTLC GUARDIAN — guardian init merge function tests
 * // tests · onthelevelconcepts.com
 * Version: 1.0.0
 * ============================================================
 *
 * Tests the merge-safety contract of `guardian init`:
 *   - Merges never overwrite the user's existing content
 *   - Every merge function is idempotent (running twice == once)
 *   - mergeClaudeSettings aborts on invalid JSON instead of clobbering
 *   - mergeClaudeSettings compares matchers as sorted token sets
 *   - mergeGitignore strips inline comments before deduping
 *   - mergeEnvExample dedupes by key, not by line
 *
 * These tests work in a temp directory created with mkdtemp so they
 * never touch real project files. Same zero-dep mini test runner
 * as injection-guard.test.js.
 *
 * Run: node tests/init.test.js
 * ============================================================
 */

import { strict as assert } from "assert";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import {
  mergeMd,
  mergeClaudeSettings,
  mergeGitignore,
  mergeEnvExample,
  copyIfNew,
  canonicalMatcher,
  findMatcherBlock,
  gitignorePathToken,
} from "../bin/guardian.js";

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

// Each test gets its own temp dir so state doesn't bleed
function withTempDir(fn) {
  const dir = mkdtempSync(path.join(tmpdir(), "guardian-test-"));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// PURE HELPER TESTS
// ---------------------------------------------------------------------------

describe("canonicalMatcher — sorted token equivalence", () => {
  test("Write|Edit canonicalizes to Edit|Write", () => {
    assert.equal(canonicalMatcher("Write|Edit"), "Edit|Write");
  });

  test("Edit|Write canonicalizes to Edit|Write", () => {
    assert.equal(canonicalMatcher("Edit|Write"), "Edit|Write");
  });

  test("single token survives", () => {
    assert.equal(canonicalMatcher("Bash"), "Bash");
  });

  test("whitespace and empty tokens are dropped", () => {
    assert.equal(canonicalMatcher("  Write | Edit  | "), "Edit|Write");
  });

  test("null/undefined produces empty string", () => {
    assert.equal(canonicalMatcher(null), "");
    assert.equal(canonicalMatcher(undefined), "");
  });
});

describe("findMatcherBlock — set-based block lookup", () => {
  test("finds block whose matcher is the same set in different order", () => {
    const arr = [{ matcher: "Edit|Write", hooks: [] }];
    const block = findMatcherBlock(arr, "Write|Edit");
    assert.ok(block !== null, "Should find existing Edit|Write block when looking for Write|Edit");
  });

  test("returns null when no matching block exists", () => {
    const arr = [{ matcher: "Bash", hooks: [] }];
    const block = findMatcherBlock(arr, "Write|Edit");
    assert.equal(block, null);
  });

  test("does not match a superset matcher", () => {
    const arr = [{ matcher: "Edit", hooks: [] }];
    const block = findMatcherBlock(arr, "Write|Edit");
    assert.equal(block, null);
  });
});

describe("gitignorePathToken — strip inline comments", () => {
  test("plain path returns itself", () => {
    assert.equal(gitignorePathToken(".env"), ".env");
  });

  test("path with trailing comment returns just the path", () => {
    assert.equal(gitignorePathToken(".env # local secrets"), ".env");
  });

  test("path with inline comment and trailing whitespace", () => {
    assert.equal(gitignorePathToken("node_modules/   # huge"), "node_modules/");
  });

  test("pure comment line returns empty", () => {
    assert.equal(gitignorePathToken("# comment"), "");
  });

  test("blank line returns empty", () => {
    assert.equal(gitignorePathToken("   "), "");
  });

  test("empty string returns empty", () => {
    assert.equal(gitignorePathToken(""), "");
  });
});

// ---------------------------------------------------------------------------
// mergeMd — markdown append-merge
// ---------------------------------------------------------------------------

describe("mergeMd — markdown append-merge", () => {
  test("preserves user content above Guardian section", () => {
    withTempDir((dir) => {
      const userPath = path.join(dir, "CLAUDE.md");
      const srcPath  = path.join(dir, "guardian-CLAUDE.md");
      writeFileSync(userPath, "# My project rules\n\nDo not delete my words.\n");
      writeFileSync(srcPath,  "# Guardian section\n\nGuardian-supplied content.\n");

      mergeMd(userPath, srcPath, "CLAUDE.md");

      const merged = readFileSync(userPath, "utf8");
      assert.ok(merged.startsWith("# My project rules"), "User content must be at the top");
      assert.ok(merged.includes("Do not delete my words"), "User text must survive");
      assert.ok(merged.includes("OTLC-GUARDIAN-START"), "Guardian section marker must be present");
      assert.ok(merged.includes("Guardian-supplied content"), "Guardian content must be appended");
    });
  });

  test("idempotent — running twice does not duplicate", () => {
    withTempDir((dir) => {
      const userPath = path.join(dir, "CLAUDE.md");
      const srcPath  = path.join(dir, "guardian-CLAUDE.md");
      writeFileSync(userPath, "# Mine\n");
      writeFileSync(srcPath,  "# Guardian\n");

      mergeMd(userPath, srcPath, "CLAUDE.md");
      const after1 = readFileSync(userPath, "utf8");

      mergeMd(userPath, srcPath, "CLAUDE.md");
      const after2 = readFileSync(userPath, "utf8");

      assert.equal(after1, after2, "Second merge must be a no-op");
    });
  });
});

// ---------------------------------------------------------------------------
// mergeClaudeSettings — JSON-aware hook merge
// ---------------------------------------------------------------------------

describe("mergeClaudeSettings — JSON hook merge", () => {
  test("ABORTS on invalid JSON instead of clobbering", () => {
    withTempDir((dir) => {
      const userPath = path.join(dir, "settings.json");
      const srcPath  = path.join(dir, "guardian-settings.json");
      writeFileSync(userPath, '{ "hooks": { trailing comma BAD JSON },}');
      writeFileSync(srcPath,  '{ "hooks": {} }');

      const userBefore = readFileSync(userPath, "utf8");

      assert.throws(
        () => mergeClaudeSettings(userPath, srcPath),
        /could not be parsed/,
        "Should throw on invalid JSON"
      );

      const userAfter = readFileSync(userPath, "utf8");
      assert.equal(userAfter, userBefore, "Invalid file must NOT be overwritten");
    });
  });

  test("preserves user's existing hooks when merging Guardian's", () => {
    withTempDir((dir) => {
      const userPath = path.join(dir, "settings.json");
      const srcPath  = path.join(dir, "guardian-settings.json");
      writeFileSync(userPath, JSON.stringify({
        hooks: {
          PreToolUse: [{
            matcher: "Bash",
            hooks: [{ type: "command", command: "node my-bash-hook.js" }],
          }],
        },
      }));
      writeFileSync(srcPath, "{}");

      mergeClaudeSettings(userPath, srcPath);

      const result = JSON.parse(readFileSync(userPath, "utf8"));
      // User's Bash hook must still be there
      const bashBlock = result.hooks.PreToolUse.find((b) => b.matcher === "Bash");
      assert.ok(bashBlock, "User's Bash matcher block must survive");
      assert.equal(bashBlock.hooks[0].command, "node my-bash-hook.js");
      // Guardian's Write|Edit hook must be added
      const writeBlock = result.hooks.PreToolUse.find((b) => b.matcher === "Write|Edit");
      assert.ok(writeBlock, "Guardian's Write|Edit block must be added");
    });
  });

  test("appends to existing reverse-order matcher block (set comparison)", () => {
    withTempDir((dir) => {
      const userPath = path.join(dir, "settings.json");
      const srcPath  = path.join(dir, "guardian-settings.json");
      // User has "Edit|Write" — Guardian wants "Write|Edit". Same set.
      writeFileSync(userPath, JSON.stringify({
        hooks: {
          PreToolUse: [{
            matcher: "Edit|Write",
            hooks: [{ type: "command", command: "node my-existing-hook.js" }],
          }],
        },
      }));
      writeFileSync(srcPath, "{}");

      mergeClaudeSettings(userPath, srcPath);

      const result = JSON.parse(readFileSync(userPath, "utf8"));
      // There should be exactly ONE matcher block, not two
      const writeEditBlocks = result.hooks.PreToolUse.filter(
        (b) => canonicalMatcher(b.matcher) === "Edit|Write"
      );
      assert.equal(writeEditBlocks.length, 1, "Must not create a duplicate parallel block");
      assert.equal(writeEditBlocks[0].hooks.length, 2, "User hook + Guardian hook");
      assert.ok(writeEditBlocks[0].hooks.some((h) => h.command === "node my-existing-hook.js"));
      assert.ok(writeEditBlocks[0].hooks.some((h) => h.command.includes("injection-guard-hook")));
    });
  });

  test("idempotent — second run does not double-register", () => {
    withTempDir((dir) => {
      const userPath = path.join(dir, "settings.json");
      const srcPath  = path.join(dir, "guardian-settings.json");
      writeFileSync(userPath, "{}");
      writeFileSync(srcPath,  "{}");

      mergeClaudeSettings(userPath, srcPath);
      const after1 = readFileSync(userPath, "utf8");

      mergeClaudeSettings(userPath, srcPath);
      const after2 = readFileSync(userPath, "utf8");

      assert.equal(after1, after2, "Second call must be a no-op");

      // Both Guardian hooks should be registered exactly once
      const parsed = JSON.parse(after2);
      const preBlock  = parsed.hooks.PreToolUse.find((b) => canonicalMatcher(b.matcher) === "Edit|Write");
      const postBlock = parsed.hooks.PostToolUse.find((b) => canonicalMatcher(b.matcher) === "WebFetch|WebSearch");
      assert.equal(preBlock.hooks.filter((h) => h.command.includes("injection-guard-hook")).length, 1);
      assert.equal(postBlock.hooks.filter((h) => h.command.includes("web-content-guard")).length, 1);
    });
  });
});

// ---------------------------------------------------------------------------
// mergeGitignore — inline-comment-aware dedupe
// ---------------------------------------------------------------------------

describe("mergeGitignore — inline-comment-aware dedupe", () => {
  test("does not re-add a path that has an inline comment in the user file", () => {
    withTempDir((dir) => {
      const userPath = path.join(dir, ".gitignore");
      const srcPath  = path.join(dir, "guardian-gitignore");
      writeFileSync(userPath, ".env # my local secrets\nnode_modules/\n");
      writeFileSync(srcPath,  ".env\nnode_modules/\ndist/\n");

      mergeGitignore(userPath, srcPath);

      const result = readFileSync(userPath, "utf8");
      // .env appears exactly once (the user's commented version)
      const envCount = result.split("\n").filter((l) => gitignorePathToken(l) === ".env").length;
      assert.equal(envCount, 1, "Must not duplicate .env");
      // dist/ was added (it wasn't in the user's file)
      assert.ok(result.includes("dist/"), "New entries must still be added");
      // User's comment survives
      assert.ok(result.includes("# my local secrets"), "User's inline comment survives");
    });
  });

  test("idempotent — second run is a no-op", () => {
    withTempDir((dir) => {
      const userPath = path.join(dir, ".gitignore");
      const srcPath  = path.join(dir, "guardian-gitignore");
      writeFileSync(userPath, "node_modules/\n");
      writeFileSync(srcPath,  ".env\ndist/\n");

      mergeGitignore(userPath, srcPath);
      const after1 = readFileSync(userPath, "utf8");

      mergeGitignore(userPath, srcPath);
      const after2 = readFileSync(userPath, "utf8");

      assert.equal(after1, after2, "Second merge must be a no-op");
    });
  });
});

// ---------------------------------------------------------------------------
// mergeEnvExample — key-based dedupe
// ---------------------------------------------------------------------------

describe("mergeEnvExample — key-based dedupe", () => {
  test("does not re-add a key with a different value", () => {
    withTempDir((dir) => {
      const userPath = path.join(dir, ".env.example");
      const srcPath  = path.join(dir, "guardian-env.example");
      writeFileSync(userPath, "DATABASE_URL=postgresql://my-real-host\n");
      writeFileSync(srcPath,  "DATABASE_URL=postgresql://localhost\nJWT_SECRET=change-me\n");

      mergeEnvExample(userPath, srcPath);

      const result = readFileSync(userPath, "utf8");
      // User's DATABASE_URL value is preserved
      assert.ok(result.includes("DATABASE_URL=postgresql://my-real-host"));
      // Guardian's DATABASE_URL value is NOT added
      assert.ok(!result.includes("DATABASE_URL=postgresql://localhost"));
      // JWT_SECRET (new key) IS added
      assert.ok(result.includes("JWT_SECRET=change-me"));
    });
  });

  test("idempotent — second run is a no-op", () => {
    withTempDir((dir) => {
      const userPath = path.join(dir, ".env.example");
      const srcPath  = path.join(dir, "guardian-env.example");
      writeFileSync(userPath, "EXISTING=value\n");
      writeFileSync(srcPath,  "NEW=value\n");

      mergeEnvExample(userPath, srcPath);
      const after1 = readFileSync(userPath, "utf8");

      mergeEnvExample(userPath, srcPath);
      const after2 = readFileSync(userPath, "utf8");

      assert.equal(after1, after2);
    });
  });
});

// ---------------------------------------------------------------------------
// copyIfNew — never-overwrite copy
// ---------------------------------------------------------------------------

describe("copyIfNew — never-overwrite copy", () => {
  test("creates new file when destination missing", () => {
    withTempDir((dir) => {
      const src = path.join(dir, "src.txt");
      const dst = path.join(dir, "subdir", "dst.txt");
      writeFileSync(src, "hello");

      copyIfNew(src, dst, "test");

      assert.ok(existsSync(dst));
      assert.equal(readFileSync(dst, "utf8"), "hello");
    });
  });

  test("does NOT overwrite existing destination", () => {
    withTempDir((dir) => {
      const src = path.join(dir, "src.txt");
      const dst = path.join(dir, "dst.txt");
      writeFileSync(src, "guardian content");
      writeFileSync(dst, "user content");

      copyIfNew(src, dst, "test");

      assert.equal(readFileSync(dst, "utf8"), "user content", "Existing file must be untouched");
    });
  });
});

// ---------------------------------------------------------------------------
// RESULTS
// ---------------------------------------------------------------------------

console.log(`\n${"─".repeat(60)}`);
console.log(`🔍 [OTLC GUARDIAN] init.test.js RESULTS`);
console.log(`   Passed : ${passed}`);
console.log(`   Failed : ${failed}`);
console.log(`   Total  : ${passed + failed}`);

if (failures.length > 0) {
  console.error(`\n❌ FAILURES:`);
  failures.forEach((f) => console.error(`   → ${f.name}: ${f.error}`));
  process.exit(1);
} else {
  console.log(`\n✅ All init tests passed.\n`);
  process.exit(0);
}
