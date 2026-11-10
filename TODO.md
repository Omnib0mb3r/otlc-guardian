# otlc-guardian TODO

## R&D AND PLAN ONLY: Self-Growing Gate spec (Michael 2026-11-10 00:09 EST, via DevNeural Lex)

Spec: C:/dev/data/lex-phone/files/c3136af8-4030-429c-94b5-5e69caa5c9ea-OTLC_Guardian_Self-Growing_Gate_Spec.md. Michael's terms: research and a plan for his approval. Nothing is built, merged, installed or wired into CI until he approves it. No brainstorm supervises otlc-guardian yet, so this waits here.

Guardian's part: Lanes 1 to 4 (Semgrep layer, guardian deploy-check, review briefs, dependency audits), Lane 5's hard-no PreToolUse hook as a Guardian component, accepted-risks files, the monthly growth loop and the coverage map. The DevNeural hardening items section belongs to DevNeural.

Deliverable: read all of this repo's code first (audit engine, rules, skill, guides). Then a full plan, per lane: what exists today with file evidence, what changes, pros and cons, blast radius (projects and hooks touched, what could regress, rollback), build order. The spec's order (deploy-check, Semgrep, briefs, growth loop) is a suggestion, not a decision. Publish it as an artifact for Michael.

Points to weigh:
- The growth loop overlaps the threat-feed spec below (2026-11-08). Merge the two into one design, not two loops.
- DevNeural already runs a cross-project write guard as a PreToolUse hook; on the live machine its matcher lacks Bash, though DevNeural's install-hooks.ts:156 and manual chapter 13 say it covers it. The hard-no hook extends or sits on that guard, never duplicates it; agree the boundary with DevNeural's Lex (brainstorm 4bbafb48) first.
- Signed Lex Phone approvals are the biggest piece: their own phase, after the hard-no hook. The same phone key may serve car box authentication, which DevNeural is designing.
- A hard no fails closed and must not disturb unattended workers that never touch the list.

## SPEC: Guardian keeps itself current (threat feed)

Added 2026-11-08 by Lex (White Board brainstorm), from Michael's ask: "write up a little spec for OTLC Guardian to check those known sources against itself, so whenever Guardian is called it is as up to date as we can make it." Not started. Start after the plan-usage hold lifts (2026-11-10 08:00 EST).

### Goal

Every time Guardian runs, in any project, its rules reflect what is currently known to be dangerous and what is currently recommended. Updates reach every project at once: the installed skill is a link to this repo's `skill/` folder, so a merged rule is live everywhere on the next run.

### Sources, by how far each is trusted

| Source | What it gives | Trust |
|---|---|---|
| Maintainer advisories, via GitHub Advisory Database and OSV.dev | known flaws in specific package versions, with exact affected ranges | highest: written by whoever shipped the fix |
| CISA Known Exploited Vulnerabilities | flaws confirmed exploited in the wild | high for urgency, narrow in scope |
| OWASP Top 10, OWASP Top 10 for LLM Applications, CWE Top 25 | classes of weakness and recommended practice | baseline; checked when a new edition is published, not weekly |
| Published audit skills and harnesses (for example cloudflare/security-audit-skill, MIT) | attack checklists, especially AI/agent and local daemon/IPC classes | ideas only; never imported as rules without the steps below |
| NVD | CVE records and severity scores | lowest: backlogs and estimated scores; used only alongside another source |

### Weekly cycle

1. Pull what changed in each source since the last run (stored cursor per source).
2. For each item, decide: already covered by a Guardian rule, new rule needed, or not applicable to code Guardian can see.
3. For a new rule: draft the rule plus two fixtures in `tests/`: a bad sample it must flag and a good sample it must not.
4. Independent review of each draft (Codex at xhigh, or a fresh Claude reviewer when Codex is unavailable), per Michael's review rule.
5. Merge only when both fixtures pass and the full audit test suite stays green. Nothing merges on one source alone: an advisory or pattern needs a second source or a reproducible fixture.
6. Changelog entry per rule, naming its sources.

### Rerun after every rule change

When rules change, run the audit across every registered project (GET /lex/portfolio for the list), not only at the next commit. Each new finding goes into that project's BUGS.md in plain words, with the rule id and source. A finding is filed only after checking it applies: the affected version is installed and the flagged code is really reached.

### Dependency advisories

Advisories against packages a project actually uses (lockfiles: package-lock.json, pnpm-lock.yaml, requirements, etc.) are matched by exact version through OSV, and filed the same way. This is separate from the static rules and catches the most likely real-world hit.

### Learning from our own bugs

Every security bug found in any of Michael's projects becomes a Guardian rule with fixtures, so the same mistake is caught everywhere after.

### Who runs it

DevNeural runs the weekly cycle as a scheduled job and files results; this repo owns the rules, fixtures and review. DevNeural's side is a change to another system: tell DevNeural's Lex what it needs (schedule, where drafts land) and document it in both manuals.

### Open points

- **Decided (Michael, 2026-11-08 02:58Z): Guardian runs on every change in every project**, not only backend code ("Guardians should run every time we're doing something to make sure we're not doing stupid shit"). Today it does not: the global rule invokes it only for backend and full-stack code before a commit, and only 3 project CLAUDE.md files name it. Make it enforced, not remembered: a commit hook every project gets (the dev-template for new projects, an installer for the existing ones), so it runs whether or not a session thinks to call it. A HIGH finding blocks the commit; lower ones are reported. Michael's global CLAUDE.md line on Guardian changes to match (his file: proposed wording goes to him).
- Related open bugs here: BUG-002 (no rules for what AI agents can write to) is the first gap the AI/agent source list should close.
- Guardian has no manual yet; this work should start one.
