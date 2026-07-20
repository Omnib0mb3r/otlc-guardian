# Guardian Audit Improvements - Handoff

This doc is self-contained. You should not need any prior conversation to act on it.

## What triggered this

`guardian audit` was run against a real-world Base44-generated CMMS project at `c:\dev\Projects\OPS\Zion CMMS` on 2026-04-27 (Guardian 1.3.1). The audit returned 9 findings: 6 CRITICAL, 3 HIGH, 0 MEDIUM, 0 LOW.

After triage, all 6 CRITICALs were false positives from a single rule (`INJ-005b`). Two of the 3 HIGH findings were real (silent catches), one was correct-but-noisy (`dangerouslySetInnerHTML` in shadcn boilerplate). Several real issues that should have been flagged were missed entirely because they sit outside the regex-audit's reach today.

The full triage:

| Finding | Verdict | Notes |
|---|---|---|
| INJ-005b at `src/pages/Assets.jsx:93,102,125,136` | False positive | `window.confirm` and JSX button label text |
| INJ-005b at `src/pages/Inventory.jsx:51` | False positive | `window.confirm` |
| INJ-005b at `base44/functions/swapInventoryQuantities/entry.ts:57` | False positive | `console.error` format string |
| ERR-001 at `base44/functions/notifyQuoteApproved/entry.ts:24,33` | True positive | Two `catch (_) {}` around optional context fetches |
| INJ-003 at `src/components/ui/chart.jsx:61` | True positive but noisy | Stock shadcn CSS-variable injection from a constant |

Issues missed by the current audit but visibly bad in the same project:

- `requiresAuth: false` directly under a comment claiming auth is required (`src/api/base44Client.js:7`)
- `setTimeout(r, 1000)` followed by an entity lookup, classic race (`base44/functions/inviteUser/entry.ts:29`)
- AI agent config granting `create/update/delete` on `QuoteLineItem` and `update` on `Inventory` with no human approval gate (`base44/agents/zion_ai_assistant.jsonc`)
- `npm:@base44/sdk` pinned to three different versions (`0.8.23`, `0.8.25`, `0.8.25`) across functions
- 708-line page file (`src/pages/AdminDashboard.jsx`)

Net read: the audit is structurally sound, but one rule is too aggressive and the rule set has gaps in places that match Guardian's stated threat model ("AI security attacks").

## Goal of this work

Cut a `1.4.0` release that fixes `INJ-005b` precision, adds the AI-agent-permission audit, adds a `setTimeout`-before-query rule, adds an SDK-version-drift rule, adds a shadcn allowlist for `INJ-003`, and adds an opt-in file-size rule. All six items below should land together. CHANGELOG, SECURITY.md, README, and tests get updated in the same release.

If scope creeps, the only items that absolutely must ship together are item 1 (regression fix) and item 2 (net-new capability that closes the marketing-vs-coverage gap). Items 3 through 6 can split off into a follow-up if needed.

## Item 1 - INJ-005b precision rewrite

### Problem

The current rule fires on any template literal containing `${}` and one or more SQL-looking words. It has no awareness of the call site. In codebases that use Base44, Supabase, Prisma, or any other no-direct-SQL ORM, every match is a false positive. First-run user trust is being burned.

### Proposed fix

Two options. Pick one or implement both as a layered defense:

**Option A - context skip-list (smaller change).** Before flagging, check the call site context of the template literal. Skip if the call site matches:

- `window.confirm(`, `confirm(`
- `window.alert(`, `alert(`
- `window.prompt(`, `prompt(`
- `console.log(`, `console.warn(`, `console.error(`, `console.info(`, `console.debug(`
- `new Error(`, `throw new Error(`, `*Error(` (any constructor ending in `Error`)
- JSX text children (between `>` and `<`)
- JSX attribute values that are not `dangerouslySetInnerHTML`, `href`, `src`, `srcDoc`, `action`, `formAction` (the dangerous-attribute list keeps separate XSS coverage intact)
- Direct return value of an arrow function or function whose name suggests a string formatter (`format*`, `toMessage`, `toLabel`, etc.)

**Option B - invert to positive SQL-call-site match (cleaner change).** Only flag template literals whose call site matches a known SQL execution pattern:

- `.query(`, `.execute(`, `.raw(`, `.unsafe(`
- `db.`, `pool.`, `connection.`, `client.` followed by any of the above
- Backtick string passed directly into an `await sql\`\`` tag where the tag is NOT `security/04-sql-guard.js`'s safe `sql` tag (the sql-guard tag is the fix, not the attack)

Option B has higher precision (zero false positives in this Zion run) and lower coverage (might miss a custom DB wrapper). Option A has lower precision but catches more attack-shape code.

**Recommendation:** ship Option B as the primary check, fall back to Option A's pattern as a secondary lower-severity hint. That way you catch the obvious cases at HIGH severity and surface the maybe-cases at MEDIUM with a "review the call site" note.

### Files to touch

- `security/03-audit.js` - the rule definition for INJ-005b
- `tests/audit.test.js` - new positive and negative fixtures (see below)

### Test fixtures

Positive (should still flag):

```js
const id = req.params.id;
await db.query(`SELECT * FROM users WHERE id = ${id}`);
```

```js
const userId = input;
await pool.execute(`UPDATE accounts SET balance = ${amount} WHERE id = ${userId}`);
```

Negative (must not flag):

```js
if (!window.confirm(`Delete ${count} items? This cannot be undone.`)) return;
```

```js
console.error(`Failed to update record ${record.id}:`, err);
```

```jsx
<Button>Delete Selected ({count})</Button>
<span>{`Hello ${name}`}</span>
```

```js
throw new Error(`Quote ${quoteId} not found`);
```

```js
import { sql } from './security/04-sql-guard.js';
const query = sql`SELECT * FROM users WHERE id = ${userId}`;
```

## Item 2 - AI agent permission audit (new rule, AGT-001)

### Problem

Guardian's runtime layer protects against prompt injection and output leakage. The audit has zero rules about *what AI agents can write to*. The Zion CMMS shipped an AI agent with `create/update/delete` on `QuoteLineItem` and `update` on `Inventory`, with the only "approval" being a politely worded line in the system prompt. That is exactly the threat surface Guardian's README claims to cover, and the audit walks past it.

### Proposed rule

New rule code: `AGT-001 - AI agent has write access to high-risk entities without visible approval gate`. Severity: HIGH.

Scan for files matching:

- `**/agents/**/*.json`
- `**/agents/**/*.jsonc`
- `**/agents/**/*.yaml`
- `**/agents/**/*.yml`
- `**/.claude/agents/**` (sub-agent configs)
- Any file whose JSON content has a top-level `tool_configs` array OR `allowed_operations` array OR `entity_name` field

In matching files, parse the JSON (use a tolerant parser for `.jsonc` to strip comments). For each entry in `tool_configs` or equivalent, check:

1. The `entity_name` (or equivalent field) matches the high-risk entity pattern list:
   - Exact: `Quote`, `Invoice`, `LineItem`, `Order`, `Payment`, `Transaction`, `Charge`, `Refund`, `Subscription`, `Customer`, `User`, `Account`, `Credential`, `ApiKey`, `Token`, `Permission`, `Role`
   - Suffix match: `*LineItem`, `*Quote`, `*Invoice`, `*Order`, `*Payment`, `*Transaction`
   - Inventory-financial: `Inventory`, `Stock`, `Warehouse` (write access to stock levels has financial impact)

2. The `allowed_operations` (or equivalent) contains any of: `create`, `update`, `delete`, `write`, `*`.

3. There is no co-located approval-gate marker. Approval-gate markers are:
   - A sibling file `approval-gate.json` or `human-in-loop.json` referenced from the agent config
   - A field `requires_approval: true` or `human_approval: true` on the same entry
   - An `otlc-guardian:agent-write-approved` audit-exempt marker on the same line

When all three conditions hit, raise `AGT-001`.

### Output shape

```
[AGT-001] AI agent has write access to high-risk entity without visible approval gate
  base44/agents/zion_ai_assistant.jsonc
    entity: QuoteLineItem
    operations: create, update, delete
    suggested fix: Add `requires_approval: true`, route writes through a server function with an explicit confirm step, or mark this finding exempt with a justification.
```

### Files to touch

- `security/03-audit.js` - new rule definition, JSON parser util (or import a tolerant JSONC parser - keep it zero-dependency, write a 30-line stripper if needed)
- `tests/audit.test.js` - fixtures
- `SECURITY.md` - new section under threat model: "Agent permission scope"
- `README.md` - add `AGT-001` to the audit rule count, mention "AI agent permission scoping" in the audit section
- `CHANGELOG.md`

### Test fixtures

Positive (should flag):

```jsonc
// tests/fixtures/agents/over-permissive.jsonc
{
  "name": "billing_assistant",
  "tool_configs": [
    {
      "entity_name": "Invoice",
      "allowed_operations": ["create", "update", "delete"]
    }
  ]
}
```

Negative (must not flag):

```jsonc
// tests/fixtures/agents/read-only.jsonc
{
  "name": "reporting_assistant",
  "tool_configs": [
    {
      "entity_name": "Invoice",
      "allowed_operations": ["read"]
    }
  ]
}
```

```jsonc
// tests/fixtures/agents/with-approval.jsonc
{
  "name": "billing_assistant",
  "tool_configs": [
    {
      "entity_name": "Invoice",
      "allowed_operations": ["create", "update"],
      "requires_approval": true
    }
  ]
}
```

## Item 3 - setTimeout-before-query (new rule, RACE-001)

### Problem

`base44/functions/inviteUser/entry.ts:29` does `await new Promise(r => setTimeout(r, 1000))` and then queries by email. Classic "sleep then read" race. If invite provisioning takes longer than 1 second, the role-update query misses silently and the user lands at the default role. Same anti-pattern shows up in any code that "waits for eventual consistency" with a hardcoded sleep.

### Proposed rule

New rule: `RACE-001 - sleep-then-query is a race condition, use polling with backoff or rely on a returned identifier`. Severity: HIGH.

Pattern: a `setTimeout`, `setInterval`, or `Promise(r => setTimeout(r, N))` within 5 lines (configurable) preceding a database/entity query call. Database/entity query calls match:

- `.filter(`, `.find(`, `.findOne(`, `.findMany(`, `.findUnique(`
- `.get(`, `.list(`, `.where(`
- `await base44.`
- `await prisma.`, `await db.`, `await client.`
- `.query(`, `.execute(`

Skip if there is an `otlc-guardian:race-allowed` marker on the sleep line or within the surrounding block.

### Files to touch

- `security/03-audit.js`
- `tests/audit.test.js`
- `CLAUDE.md` (add a sentence in the senior-dev rules about race conditions and "sleep then read")
- `STANDARDS.md` (add the polling-with-backoff pattern as the approved approach)
- `CHANGELOG.md`

### Test fixtures

Positive:

```ts
await someExternalCall(input);
await new Promise(r => setTimeout(r, 1000));
const records = await base44.entities.User.filter({ email });
```

Negative:

```ts
// Polling with backoff, no fixed sleep before the query
let attempts = 0;
while (attempts < 5) {
  const records = await base44.entities.User.filter({ email });
  if (records.length) return records[0];
  await new Promise(r => setTimeout(r, 200 * Math.pow(2, attempts)));
  attempts++;
}
```

```ts
// Sleep is for rate limiting between writes, not before a read
for (const item of items) {
  await write(item);
  await new Promise(r => setTimeout(r, 300));
}
```

The negative-second case is tricky because the rule will likely fire on it. Decide: either accept the false positive and rely on the exempt marker, or tighten the rule so it requires the query to use the same variable that flowed into the preceding write/call. The simpler version (accept FP, use marker) is fine for a first cut.

## Item 4 - SDK version drift (new rule, DEP-003)

> **Corrected 2026-07-20.** This item originally specified rule id `DEP-001`, which is
> already in use by `DEP-001 - No health check endpoint found` (shipped since 1.2.4,
> covered by tests). Implementing as originally written would have put two rules under
> one id and broken per-id filtering for JSON consumers and CI gates. Reassigned to
> `DEP-003`; `DEP-002` is the committed-`.env` rule. Tracked as BUG-004.

### Problem

In Deno-based projects (Base44, Supabase Edge Functions, Deno Deploy), `npm:` imports pin a version inline. Across multiple entry files, the same package can drift. The Zion CMMS has `npm:@base44/sdk@0.8.23`, `npm:@base44/sdk@0.8.25`, and `npm:@base44/sdk@0.8.25` in three different functions. Different SDK versions = different behaviors = future debugging tax.

### Proposed rule

New rule: `DEP-003 - inconsistent npm: import versions across project files`. Severity: MEDIUM.

Scan all `.ts`, `.tsx`, `.js`, `.mjs`, `.jsx` files for imports matching the pattern `from ['"]npm:([^'"@]+)@([^'"]+)['"]`. Group by package name. If a package appears at more than one version across the scanned files, raise `DEP-003` once per package, listing every file and pinned version.

### Output shape

```
[DEP-003] Inconsistent npm: import version for @base44/sdk
  Found 2 distinct versions across 3 files:
    @base44/sdk@0.8.23
      base44/functions/inviteUser/entry.ts:1
    @base44/sdk@0.8.25
      base44/functions/notifyQuoteApproved/entry.ts:1
      base44/functions/swapInventoryQuantities/entry.ts:1
  Suggested fix: pin every file to the same version, or move shared dependencies into an import map.
```

### Files to touch

- `security/03-audit.js`
- `tests/audit.test.js`
- `CHANGELOG.md`

### Test fixtures

Positive: two test files importing different versions of the same `npm:` package.

Negative: two test files importing the same version, or two test files importing different packages.

## Item 5 - shadcn `INJ-003` allowlist

### Problem

`INJ-003` correctly flags `dangerouslySetInnerHTML`, but the shadcn `chart.jsx` component (which is generated boilerplate copied into many React projects) uses it for static CSS variable injection. Every shadcn user gets one HIGH finding they have to triage.

### Proposed fix

Add a built-in audit allowlist for the exact shadcn pattern. The shadcn chart component looks like:

```jsx
<style
  dangerouslySetInnerHTML={{
    __html: Object.entries(THEMES)
      .map(([theme, prefix]) => `... ${chartId} ... ${value}`)
      .join('\n'),
  }}
/>
```

Identification: `dangerouslySetInnerHTML` whose `__html` value is a `.join(`-terminated chain of `.map(` calls operating on a constant object, AND the file path matches `**/components/ui/chart.{js,jsx,ts,tsx}` AND the file's first 30 lines contain a comment or import indicating shadcn provenance.

If any of those don't match, the rule still fires. The allowlist is narrow on purpose.

Alternative simpler approach: just check the file path. If it's exactly `**/components/ui/chart.{js,jsx,ts,tsx}`, skip the rule. Document this in the rule description so users who modified the file know to remove the path skip.

### Recommendation

Path-based skip is fine for a first cut. The more sophisticated AST match is a follow-up.

### Files to touch

- `security/03-audit.js`
- `tests/audit.test.js`
- `CHANGELOG.md`

## Item 6 - opt-in file size rule (QUAL-001)

### Problem

Guardian's behavior layer (`STANDARDS.md`) implies decomposition. The audit doesn't enforce it. The Zion CMMS shipped `src/pages/AdminDashboard.jsx` at 708 lines and `src/components/workorders/WorkOrderPanel.jsx` at 486 lines. Quality issue, not security.

### Proposed rule

New rule: `QUAL-001 - file exceeds size threshold, consider decomposition`. Severity: LOW. Default-disabled. Opt-in via flag `--enable-quality` or via `auditConfig.enableQuality: true` in config.

Threshold: 400 lines for `.jsx`/`.tsx` files (UI components/pages), 600 lines for `.js`/`.ts` (services/utils). Both configurable.

### Files to touch

- `security/03-audit.js`
- `tests/audit.test.js`
- `README.md` (add the `--enable-quality` flag, document the rule)
- `CHANGELOG.md`

### Recommendation

This is the lowest-priority item. If you're tight on time, ship 1-5 in `1.4.0` and push 6 to `1.5.0`. It changes Guardian's identity slightly (security-tool toward style-linter) and deserves its own deliberate decision.

## Release plan

Target: `1.4.0`.

Order of work:

1. Items 1, 5 in one commit (precision fixes, lowest risk).
2. Item 4 in one commit (cleanest scope, reads the file system, easy to test).
3. Item 3 in one commit (regex-based, similar shape to existing rules).
4. Item 2 in its own commit (largest scope, JSON parsing, threat model expansion). Save for last so the smaller commits don't get held up by item 2's design questions.
5. Item 6 only if time allows. Otherwise tag for `1.5.0`.

CHANGELOG entry shape:

```
## 1.4.0 - YYYY-MM-DD

### Added
- AGT-001: AI agent permission audit. Flags agent configs that grant write/delete access to high-risk entities (Quote, Invoice, Inventory, etc.) without an approval gate.
- RACE-001: setTimeout-before-query race condition detection.
- DEP-003: inconsistent npm: import version detection across Deno projects.
- QUAL-001 (opt-in via --enable-quality): file size limits.

### Changed
- INJ-005b precision rewrite. The rule now uses positive SQL-call-site matching as the primary check and context-aware skip patterns as a secondary fallback. False positive rate on no-direct-SQL codebases reduced from ~100% to <5%.
- INJ-003 now skips the stock shadcn chart.jsx pattern by default.

### Migration notes
- If you suppressed INJ-005b findings in CI before, re-run after upgrading. The rule's behavior is materially different.
- If your project has a real shadcn chart.jsx with custom modifications, audit it manually or remove the path-skip in your fork.
```

## Open questions to resolve before coding

1. For `AGT-001` (item 2), is the high-risk entity name list canonical or community-contributed? If community-contributed, where does it live? (Recommendation: ship a hardcoded list in `security/03-audit.js` with a comment pointing at a future `agent-risk-entities.json` config file. Keep it zero-dependency.)
2. For `INJ-005b` Option B (inverted positive match), what about custom DB wrappers? Decide whether to ship a configurable allowlist of "things that mean SQL execution in your project."
3. For `RACE-001`, should the rule fire on `setInterval` too, or only `setTimeout`? Recommendation: both, but `setInterval` is rare enough in modern code that the FP risk is low.
4. For `DEP-003`, should it also catch CDN imports (`https://esm.sh/...`, `https://deno.land/x/...`)? Probably yes, same logic, different regex.
5. CHANGELOG format - the current `CHANGELOG.md` is 64KB. Confirm the existing format and style before writing the 1.4.0 entry.

## Files to read before starting

- `security/03-audit.js` - this is where most of the work happens.
- `tests/audit.test.js` - to match the existing fixture style.
- `CLAUDE.md` and `STANDARDS.md` - so the new behavior-rule additions match the existing voice.
- `SECURITY.md` - threat model section, for item 2's expansion.
- `CHANGELOG.md` - format and style of past releases.

## Out of scope for this work

- Changing the runtime guard (`security/01-injection-guard.js`, `security/injection_guard.py`). Nothing in the Zion CMMS audit run pointed at runtime guard issues.
- Changing the hooks (`.claude/hooks/`). Same.
- Touching `02-code-security.js` or `04-sql-guard.js`. Same.
- Adding new agent compatibility rows or hook integrations. Different scope, different release.
