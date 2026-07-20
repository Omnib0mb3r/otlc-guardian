<!--
Source   : The Lazy Developer (thelazydeveloper.org)
Guide    : https://www.thelazydeveloper.org/authorization-idor-guide
Index    : https://www.thelazydeveloper.org/resources
Retrieved: 2026-07-20
Stored verbatim. Do not edit the body; re-pull from the source instead.
-->
# Authorization and IDOR: "Authenticated" Is Not "Authorized"

**The mistake in one sentence:** an endpoint checks that *someone* is logged in, then performs a destructive or data-revealing action on *any* object by ID — without checking whether the logged-in user actually owns, is assigned to, or has permission over that specific object.

---

## What it looks like

```typescript
// app/api/documents/[id]/route.ts — "secured" but not really
export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const user = await getUser(req);
  if (!user) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Any logged-in user reaches this line — including the lowest-privilege role.
  // Nothing here checks that `user` owns, is assigned to, or is even allowed
  // to touch document `params.id`.
  await db.documents.delete({ where: { id: params.id } });

  return Response.json({ success: true });
}
```

This passes every obvious test: log in, delete your own document, it deletes. The bug only shows up when you delete *someone else's* document by ID — which works exactly the same way, because the code never checks whose document it is.

The same shape shows up on `GET` and `PATCH` too, and it's often worse there because it's silent: a `GET /api/libraries/[id]` with only an auth check (no ownership/assignment check) means any authenticated user can read *any* other tenant's/customer's/team's private record just by guessing or incrementing an ID. A `PATCH` with the same gap means they can also write to it.

## Why AI tools generate this

Authorization has **two layers**, and AI scaffolding tends to generate only the first one convincingly:

1. **Authentication** — "is this a real, logged-in user?" This is easy to scaffold because it's a single, reusable check (`getUser()`, `requireAuth`) that looks identical on every route, so a model reproduces it faithfully everywhere.
2. **Authorization / object-level access control** — "is *this* user allowed to touch *this specific* object?" This is different on every route (ownership? team membership? assignment? role?), so it requires actually reasoning about the data model each time — and that's exactly the step that gets skipped when the immediate goal is "make the delete button work."

The result is a codebase where auth *looks* consistent (every route has the same `getUser()` call at the top) which paradoxically makes the missing object-level check harder to spot in review — the route "has security code," just not the right kind.

This gets worse through **copy-paste drift**: once one route correctly implements assignment-scoped access control (say, a `consent` or `invoice` endpoint that properly checks a join table), a very similar sibling route (`libraries/[id]`, `folders/[id]`) gets scaffolded by analogy but the assignment check doesn't make the copy — because the AI (or the developer skimming its output) sees "auth check present" and moves on. One repo in this series had a working, correct assignment-check pattern sitting right next to three routes that never called it.

## Why it's dangerous

- **Cross-tenant data exposure.** Any authenticated user — including your cheapest, lowest-trust account tier — can read or modify data belonging to other users, teams, or customers, just by changing an ID in the URL.
- **Destructive actions at scale.** A `DELETE` with no ownership check is scriptable: iterate IDs 1 through N, delete everything. This is the highest-impact version of the bug because it's not just a read leak, it's data loss.
- **It's invisible in normal QA.** Every manual test ("can I delete my own thing? yes") passes. The bug only appears when someone deliberately (or accidentally, via a stale bookmark or shared link) touches an ID that isn't theirs.
- **Enumerable IDs make it worse.** Sequential integer IDs or predictable slugs turn this from "you'd have to guess a UUID" into "you can just increment a counter."

## How to check your own app

```bash
# 1. Find every dynamic-ID route (the classic IDOR shape)
grep -rln "params\.id\|params\[.id.\]\|req\.params\.id\|:id" --include="*.ts" --include="*.tsx" app/api server/src/routes

# 2. For each one, check whether the handler does anything with the ID besides
#    an auth check before querying/mutating by that ID. Look for a SECOND
#    check — ownership, assignment, or role — after the auth check:
grep -A 20 "getUser(req)\|requireAuth" <route-file> | grep -E "owner|assign|role|can\(|permission"
# If you don't see a second check referencing the object owner/assignment,
# that route is very likely IDOR-vulnerable.

# 3. Specifically flag DELETE and PATCH handlers with only one guard clause —
#    these are the highest-impact version of the bug
grep -B5 "\.delete(\|\.destroy(\|admin\.from.*delete" --include="*.ts" -r app/api server/src/routes | grep -B5 "delete" | grep -c "getUser\|requireAuth"

# 4. Look for a cache layer keyed on an object ID without the user ID folded
#    into the key — this is the same bug one level down the stack
grep -rn "cache\.\(get\|set\)(" --include="*.ts" . | grep -v "userId\|user_id"
```

Then do it by hand for the routes that matter most: pick your 5 most sensitive object types (whatever holds customer data, billing info, or is destructive) and, for each one, write down in plain English: *"what proves this specific user is allowed to touch this specific object?"* If the answer is "nothing, we just checked they're logged in," you've found the bug.

## The fix

Centralize object-level access checks into one helper, and make every route that takes an `:id` call it. The specific rule depends on your data model, but the shape is always: **look up the ownership/assignment relationship, and 403 if it doesn't include this user** — separately from, and after, the authentication check.

```typescript
// lib/access-control.ts — one place, reused everywhere
export async function assertObjectAccess(
  userId: string,
  userRole: string,
  objectId: string,
  action: 'view' | 'edit' | 'delete'
): Promise<void> {
  // Elevated roles bypass the assignment check but NOT the permission check
  if (!roleCan(userRole, action)) {
    throw new ForbiddenError(`Role ${userRole} cannot ${action}`);
  }

  // Roles that are scoped to specific objects (not global admins) must have
  // an explicit assignment row — this is the check that was missing above
  if (isScopedRole(userRole)) {
    const assignment = await db.userAssignments.findFirst({
      where: { userId, objectId },
    });
    if (!assignment) {
      throw new ForbiddenError('Not assigned to this object');
    }
  }
}
```

```typescript
// app/api/documents/[id]/route.ts — fixed
export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const user = await getUser(req);
  if (!user) return Response.json({ error: 'Unauthorized' }, { status: 401 });

  try {
    await assertObjectAccess(user.id, user.role, params.id, 'delete');
  } catch (e) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  await db.documents.delete({ where: { id: params.id } });
  return Response.json({ success: true });
}
```

The same principle applies to caches: **key every cache entry that could contain user-specific or gated content on the user ID, not just the object ID**, and check ownership *before* the cache read, not after.

```typescript
// Broken: cache key doesn't include userId, and the ownership check
// only runs on a cache MISS — a cache HIT skips authorization entirely
const cached = await redis.get(`thumbnail:${videoId}`);
if (cached) return cached; // <-- returns another user's signed URL if they share a videoId

// Fixed: scope the key to the requester, and check ownership before any cache read
async function getThumbnail(userId: string, videoId: string) {
  await assertObjectAccess(userId, role, videoId, 'view'); // check FIRST
  const cacheKey = `thumbnail:${userId}:${videoId}`;
  const cached = await redis.get(cacheKey);
  if (cached) return cached;
  // ...generate, cache under the scoped key, return
}
```

## Checklist

- [ ] Every route that takes an object ID (`:id`, `[id]`) has an authorization check *in addition to* an authentication check — ownership, team/assignment membership, or role, verified against the database.
- [ ] `DELETE` and `PATCH` handlers are audited first — they're the highest-impact version of this bug.
- [ ] Object-level access checks live in one shared helper/middleware, not copy-pasted per route — so a fix in one place fixes it everywhere.
- [ ] Any cache keyed on an object ID also includes the requesting user's ID in the key (or isn't used for anything that varies per-user).
- [ ] Cache reads happen *after* an authorization check, never before.
- [ ] You've picked your 5 most sensitive object types and can articulate, for each, exactly what proves a given user may touch a given object.
- [ ] IDs for sensitive objects aren't sequential/guessable where that matters (defense in depth — not a substitute for the access check above).

## Prompt your AI assistant

```
Audit this repository for IDOR (Insecure Direct Object Reference) and missing
object-level authorization.

For every API route that accepts an object ID (a URL path param like [id] or
:id, or an ID field in the request body), check:

1. Does the handler verify the requesting user is authenticated? (First gate.)
2. SEPARATELY, does it verify the requesting user actually owns, is assigned
   to, or has a role-based right over THIS SPECIFIC object — via a database
   lookup (an ownership column, an assignment/junction table, or an
   equivalent check) — before reading, writing, or deleting it? Flag any
   route that has gate 1 but not gate 2.

3. Prioritize DELETE and PATCH/PUT handlers — these are the highest-impact
   version of this bug.

4. Check any caching layer (Redis, in-memory, CDN) for cache keys built only
   from an object ID without the requesting user's ID folded in, and confirm
   the authorization check happens before the cache is read, not after.

5. Check whether object-level access logic is duplicated across many similar
   routes (e.g. several `[id]/route.ts` files) versus centralized in one
   shared helper — duplication is how these gaps slip in silently when a new
   similar route is added later.

For each finding: file and line, a concrete exploit scenario (what would an
authenticated-but-unauthorized user be able to do), and a fix that reuses any
existing correct access-control pattern already present elsewhere in this
codebase. Do not fix anything yet — just report.
```
