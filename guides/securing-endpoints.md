<!--
Source   : The Lazy Developer (thelazydeveloper.org)
Guide    : https://www.thelazydeveloper.org/securing-endpoints-guide
Index    : https://www.thelazydeveloper.org/resources
Retrieved: 2026-07-20
Stored verbatim. Do not edit the body; re-pull from the source instead.
-->
# Securing Endpoints: Stop Trusting Whoever Can Reach the URL

**The mistake in one sentence:** AI coding tools happily generate an endpoint that does something powerful (sends an email, triggers a webhook side-effect, writes to a database) without asking "who is allowed to call this?", because nobody asked it to.

---

## What it looks like

An AI assistant scaffolds a "send welcome email" endpoint that's called from your Stripe webhook handler after a successful purchase. It works. You test it. You ship it. Nobody adds authentication, because the *happy path* (webhook fires, email goes out) never touches an unauthenticated request.

```typescript
// api/send-welcome-email.ts — looks done, isn't
export default async function handler(req: Request, res: Response) {
  const { customerEmail, customerName, courseLink } = req.body;

  await sendEmail({
    to: customerEmail,
    from: 'noreply@example.com',
    subject: `Welcome, ${customerName}!`,
    html: `<p>Hi ${customerName}, here's your course: <a href="${courseLink}">${courseLink}</a></p>`,
  });

  return res.status(200).json({ sent: true });
}
```

This is publicly reachable at `POST /api/send-welcome-email`. There is no auth check, no shared secret, no rate limit. URLs like this leak via browser dev tools, source maps, or just guessing, and anyone who finds it can:

- Send a branded email **from your domain** to any address they choose, with any name and any link they choose. That's a phishing tool with your sender reputation attached.
- Burn your email-provider quota (and possibly get your sending domain blacklisted).
- Flood your own inbox if there's a matching "admin notification" endpoint with the same problem.

This exact pattern shows up again and again: a webhook or admin action calls a second internal endpoint over plain HTTP, and that internal endpoint is left open because "only the webhook calls it," until someone else finds it.

## Why AI tools generate this

AI coding assistants are optimized to produce code that satisfies the request and passes the obvious test: "does the email send when the webhook fires?" Authentication is a *cross-cutting concern*: it's not implied by "build an endpoint that sends a welcome email," so a model has to proactively add it, and proactively adding unrequested code is exactly the kind of thing generation stops short of unless you ask. The result is an endpoint that is functionally complete and security-incomplete at the same time, and both look identical in a quick manual test.

The same blind spot produces a second, sneakier bug: **trusting identity fields from the request body.** An endpoint that receives `userId` or `email` in the POST body and uses it directly, instead of deriving it from a verified session or token, lets anyone impersonate anyone just by changing the JSON they send.

```typescript
// Also broken: identity from the body, not from a verified session
const { userId, email } = req.body;
await db.profiles.update({ where: { id: userId }, data: { marketing: true } });
```

A third variant is **header injection into outgoing email.** A contact-form endpoint that builds a raw email message by string-interpolating user input into headers (`From`, `Subject`, `Reply-To`), with nothing stripping `\r\n`, lets an attacker inject extra headers, most dangerously `Bcc:`, and turn your contact form into a spam relay:

```typescript
// Vulnerable: no CRLF stripping, weak validation
const message = `From: "${name}" <noreply@example.com>\r\nReply-To: ${email}\r\nSubject: ${subject}\r\n\r\n${body}`;
// subject = "Hi\r\nBcc: victim1@evil.com,victim2@evil.com" sails right through
// if the validation regex only checks a loose charset (e.g. \s which matches \r\n)
```

## Why it's dangerous

- **Open relay / phishing-as-a-service.** Someone scripts requests against your endpoint and sends convincing, branded phishing emails that appear to come from your real domain.
- **Reputation and deliverability damage.** Your sending domain gets flagged as a spam source; legitimate transactional email (password resets, receipts) starts landing in spam for *everyone*.
- **Quota exhaustion and cost.** Transactional email providers bill per send or cap volume; an attacker can drain your quota or trigger unexpected charges.
- **Indirect PII disclosure.** An endpoint that also accepts a `userId` and pulls that user's name/profile data to include in the email gives an attacker an oracle for enumerating or exfiltrating account data tied to arbitrary IDs.
- **Header injection turns "send an email" into "send arbitrary emails to arbitrary people using your infrastructure":** full control of `Bcc`/`Cc`, and in some mail libraries, the message body itself.

## How to check your own app

Run these checks against your own codebase (adjust paths for your stack):

```bash
# 1. Find all API route handlers
grep -rn "export default async function handler\|export async function POST\|app.post\|router.post" --include="*.ts" --include="*.tsx" .

# 2. For each one, check whether it verifies a session/token before doing anything
#    Look specifically for routes with NO match on these auth patterns:
grep -L "requireAuth\|verifyToken\|getUser(\|auth.uid()\|Authorization" $(grep -rl "export default async function handler\|app.post" --include="*.ts" .)

# 3. Find places that trust body-supplied identity instead of a verified session
grep -rn "req.body.userId\|req.body.email\|body\.userId\|body\.email" --include="*.ts" .
# For each hit: is userId/email later used to authorize an action, or just derived
# from req.user / a verified JWT? If it comes from the body, that's the bug.

# 4. Find raw email/header construction that could be CRLF-injected
grep -rn "From:.*\${" --include="*.ts" .
grep -rn "\\\\r\\\\n" --include="*.ts" .
```

Also manually list every endpoint that:
- is called *by your own backend* (webhook → internal endpoint, cron → internal endpoint), and
- assume that because "only we call it," it doesn't need its own auth.

That assumption is almost always wrong the moment the URL is guessable or shows up in a network tab.

## The fix

**Rule of thumb: every endpoint needs to answer "who's allowed to call this?", even the ones you think are internal-only.** There are three common, correct patterns:

1. **User-facing action → require a verified session/JWT, and derive identity from it, never from the body.**
2. **Internal service-to-service call (webhook → internal endpoint) → require a shared secret header**, checked with a constant-time comparison, failing closed if the secret isn't configured.
3. **Admin-only action → require a verified admin session**, checked server-side against the database, not just a client-side route guard.

```typescript
// api/lib/auth.ts — shared helpers
import { timingSafeEqual } from 'crypto';

export function verifyInternalSecret(req: Request): boolean {
  const expected = process.env.INTERNAL_API_SECRET;
  const provided = req.headers['x-internal-secret'];
  if (!expected) return false; // fail CLOSED if unset, never fail open
  if (typeof provided !== 'string' || provided.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
}

export async function verifyUser(req: Request): Promise<{ id: string; email: string } | null> {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return null;
  const { data, error } = await supabaseAdmin.auth.getUser(token);
  if (error || !data.user) return null;
  return { id: data.user.id, email: data.user.email! };
}
```

```typescript
// api/send-welcome-email.ts — fixed
export default async function handler(req: Request, res: Response) {
  if (!verifyInternalSecret(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Even internal calls should pass a structured, validated payload —
  // Zod-validate it, don't just trust the shape.
  const parsed = welcomeEmailSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid payload' });

  await sendEmail({
    to: parsed.data.customerEmail,
    from: 'noreply@example.com',
    subject: `Welcome, ${escapeHtml(parsed.data.customerName)}!`,
    html: renderWelcomeTemplate(parsed.data), // template escapes all interpolated values
  });

  return res.status(200).json({ sent: true });
}
```

```typescript
// The caller (your webhook handler) sends the secret on every internal call
await fetch(`${INTERNAL_BASE_URL}/api/send-welcome-email`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'x-internal-secret': process.env.INTERNAL_API_SECRET!,
  },
  body: JSON.stringify({ customerEmail, customerName, courseLink }),
});
```

And to stop header injection, validate *and* strip at the point of use. Don't rely on validation alone: the next person who calls the function may skip it.

```typescript
// Reject newlines at the schema level
const emailFieldSchema = z.string().max(200).regex(/^[^\r\n]*$/, 'No line breaks allowed');

// AND defensively strip at the email-sending boundary, so a bypass anywhere
// upstream still can't inject headers
function sanitizeHeaderValue(value: string): string {
  return value.replace(/[\r\n]/g, '');
}
```

## Checklist

- [ ] Every endpoint that writes data, sends email, or triggers a side effect has an explicit auth check, no exceptions for "internal" endpoints.
- [ ] Internal service-to-service calls use a shared secret, verified with a constant-time comparison, and **fail closed** (reject) if the secret env var is missing.
- [ ] User identity (`userId`, `email`, `role`) is always derived from a verified session/JWT, never read from the request body.
- [ ] Admin actions are checked against the database (a real `is_admin`/`role` lookup) server-side, not just gated by a client-side route guard.
- [ ] Any code that builds raw email headers strips `\r\n` from every interpolated value, in addition to schema-level validation.
- [ ] You've grepped for every `app.post`/`export default async function handler`/route file and can account for the auth story of each one.
- [ ] Error responses from these endpoints don't leak internal error details (see the guide on secrets & data leakage).

## Prompt your AI assistant

```
Audit this repository for unauthenticated or under-authenticated API endpoints.

For every API route handler (Express routes, Next.js API routes/route handlers,
Vercel serverless functions, or equivalent in this stack), check:

1. Does it require a verified session, JWT, or API token before doing anything
   state-changing (write, email send, external API call)? Flag any handler that
   doesn't check auth before its first side effect.

2. Does it derive user identity (userId, email, role) from a verified
   session/token, or does it trust `userId`/`email`/`role` fields from the
   request body/query string? Flag the latter — that's an impersonation bug.

3. For any endpoint that is only ever supposed to be called by our own backend
   (e.g. a webhook handler calling an internal email/notification endpoint),
   confirm there's a shared-secret check using a constant-time comparison that
   FAILS CLOSED (rejects the request) if the secret env var is missing or
   unset. Flag any that fail open.

4. For any code that constructs raw email headers (From/To/Subject/Reply-To)
   by string interpolation, confirm every interpolated value is stripped of
   \r and \n and that the input schema also rejects line breaks. Flag any
   missing this.

For each finding, give me: the file and line, a one-line description of the
exploit, and a concrete fix using patterns already present elsewhere in this
codebase where possible. Do not fix anything yet — just report.
```
