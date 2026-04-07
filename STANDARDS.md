# OTLC Guardian — Technology Standards
# // stack standards · onthelevelconcepts.com
# Version: 1.2.0
#
# READ THIS FILE ALONGSIDE CLAUDE.md
#
# CLAUDE.md = HOW to build (rules and behavior)
# STANDARDS.md = WHAT to build WITH (tools, structure, patterns)
#
# These are not preferences. They are the approved stack.
# Every choice here is time-hardened, widely adopted, maintained
# by active communities, and battle-tested in production.
#
# Junior developers guess. Senior developers reach for proven tools.
# This file is what Claude reaches for. Always.

---

## PART 1 — STACK SELECTION PHILOSOPHY

Before writing a single line of code, ask these questions in order:

1. Is there a battle-tested library for this need?
2. Is it actively maintained — commits within the last 6 months?
3. Does it have >500k weekly downloads or documented enterprise adoption?
4. Does it have TypeScript types maintained by the library itself?

If all four: use it. If none: build it following the patterns in this document.

**The goal is code that any senior developer on any team can sit down with
and immediately understand without a guided tour. Obscure choices are a
form of technical debt. Standard choices are a form of respect.**

---

## PART 2 — PROJECT ARCHITECTURE AND FOLDER STRUCTURE

### Node.js / TypeScript API

```
project-root/
├── src/
│   ├── config/
│   │   └── index.ts              ← single typed config module, reads all env vars
│   ├── lib/
│   │   ├── logger.ts             ← Pino instance, exported for use everywhere
│   │   ├── db.ts                 ← Prisma client singleton
│   │   └── redis.ts              ← Redis client singleton
│   ├── middleware/
│   │   ├── auth.ts               ← JWT verification middleware
│   │   ├── requestId.ts          ← UUID injection middleware
│   │   ├── validate.ts           ← Zod schema validation middleware factory
│   │   └── rateLimit.ts          ← rate limiting middleware
│   ├── modules/
│   │   └── [feature]/
│   │       ├── [feature].routes.ts      ← route definitions only
│   │       ├── [feature].controller.ts  ← request/response handling
│   │       ├── [feature].service.ts     ← business logic
│   │       ├── [feature].schema.ts      ← Zod schemas and inferred types
│   │       └── [feature].test.ts        ← colocated tests
│   ├── types/
│   │   └── index.ts              ← shared TypeScript types and interfaces
│   └── server.ts                 ← app setup, middleware registration, routes
├── prisma/
│   ├── schema.prisma
│   └── migrations/
├── tests/
│   └── integration/
├── .env.example
├── tsconfig.json
├── vitest.config.ts
├── package.json
└── Dockerfile
```

### Python / FastAPI API

```
project-root/
├── app/
│   ├── core/
│   │   ├── config.py             ← pydantic-settings Settings class
│   │   ├── logging.py            ← structlog configuration
│   │   └── security.py           ← JWT, password hashing utilities
│   ├── db/
│   │   ├── session.py            ← SQLAlchemy engine and session factory
│   │   └── base.py               ← declarative base
│   ├── middleware/
│   │   ├── request_id.py
│   │   └── rate_limit.py
│   ├── modules/
│   │   └── [feature]/
│   │       ├── router.py
│   │       ├── service.py
│   │       ├── schemas.py        ← Pydantic models
│   │       ├── models.py         ← SQLAlchemy models
│   │       └── test_[feature].py
│   └── main.py                   ← FastAPI app setup and router registration
├── alembic/
│   ├── versions/
│   └── env.py
├── tests/
│   └── integration/
├── .env.example
├── pyproject.toml
├── requirements.txt
└── Dockerfile
```

### React / Vite Frontend

```
project-root/
├── src/
│   ├── components/
│   │   ├── ui/                   ← shadcn/ui base components (do not modify directly)
│   │   └── [feature]/            ← feature-specific composed components
│   ├── hooks/
│   │   └── use[Feature].ts       ← TanStack Query wrappers and custom hooks
│   ├── lib/
│   │   ├── api-client.ts         ← axios instance with interceptors
│   │   ├── query-client.ts       ← TanStack Query client configuration
│   │   └── utils.ts
│   ├── pages/
│   │   └── [page]/
│   │       ├── index.tsx
│   │       └── [page].test.tsx
│   ├── store/
│   │   └── [feature].store.ts    ← Zustand stores (UI/client state only)
│   ├── types/
│   │   └── index.ts
│   ├── App.tsx                   ← router, global providers, error boundaries
│   └── main.tsx                  ← React root, QueryClientProvider
├── public/
├── .env.example
├── vite.config.ts
├── tailwind.config.ts
└── tsconfig.json
```

### Architecture Rules
- **Modules are vertical slices** — routes, controller, service, schema, test all live together
- **No circular imports** — lib imports nothing from modules; modules import from lib/core
- **One responsibility per file** — routes do not contain business logic; services do not parse HTTP
- **Tests live next to the code they test** — not in a separate top-level test directory
- **Config is always injected** — never import config directly inside business logic functions

---

## PART 3 — NODE.JS / TYPESCRIPT STACK

### Runtime and Language
- **Node.js 20 LTS** minimum — never use non-LTS versions in production
- **TypeScript 5+** — always, no exceptions. JavaScript-only = immediate technical debt.

### TypeScript Configuration

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "noImplicitAny": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "exactOptionalPropertyTypes": true,
    "forceConsistentCasingInFileNames": true,
    "esModuleInterop": true,
    "skipLibCheck": false,
    "resolveJsonModule": true,
    "declaration": true,
    "sourceMap": true
  },
  "include": ["src"],
  "exclude": ["node_modules", "dist"]
}
```

### ESLint Configuration

```json
{
  "extends": [
    "eslint:recommended",
    "plugin:@typescript-eslint/strict-type-checked",
    "plugin:@typescript-eslint/stylistic-type-checked"
  ],
  "plugins": ["@typescript-eslint"],
  "parser": "@typescript-eslint/parser",
  "parserOptions": { "project": true },
  "rules": {
    "@typescript-eslint/no-explicit-any": "error",
    "@typescript-eslint/no-floating-promises": "error",
    "@typescript-eslint/no-misused-promises": "error",
    "@typescript-eslint/await-thenable": "error",
    "@typescript-eslint/no-unused-vars": "error",
    "no-console": "error",
    "eqeqeq": ["error", "always"],
    "no-var": "error",
    "prefer-const": "error"
  }
}
```

### Package Management
- **pnpm** — preferred for speed and disk efficiency
- **npm** with committed `package-lock.json` — acceptable for single-package projects
- Pin exact versions in production: `"express": "4.18.2"` not `"^4.18.2"`
- Run `npm audit` before every release

### Web Framework
- **Fastify 4+** — preferred for new projects (faster, better TS support)
- **Express 4+** with **Helmet.js** — acceptable for teams already on Express
- Never use bare `http`/`https` Node modules for production servers
- Always configure body size limits, explicit CORS allowlist, and security headers

```typescript
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';

const app = express();
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') ?? [],
  credentials: true,
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
```

### Input Validation
- **Zod** — always. Runtime validation AND TypeScript type inference from a single schema.
- Schema-first: define Zod schema, infer TypeScript type from it — never the reverse
- Validate at the boundary — in the controller before the service layer
- Reject unexpected fields with `.strict()` on all object schemas

```typescript
import { z } from 'zod';

export const CreateUserSchema = z.object({
  email:    z.string().email().max(255),
  password: z.string().min(12).max(128),
  name:     z.string().min(1).max(100),
}).strict();

export type CreateUserInput = z.infer<typeof CreateUserSchema>;

// Validation middleware factory
export function validate(schema: z.ZodSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      return sendError(res, 422, 'ERR_VALIDATION',
        result.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join(', '),
        req.requestId);
    }
    req.body = result.data;
    next();
  };
}
```

### Logging
- **Pino** — fastest Node.js logger, JSON-native, minimal overhead
- **Winston** — acceptable when multiple transport targets are needed
- Always configure log level from `LOG_LEVEL` environment variable
- Always include `requestId` in every log entry via child logger
- Always redact sensitive fields: authorization headers, passwords, tokens

```typescript
import pino from 'pino';

export const logger = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  base:  { service: process.env.SERVICE_NAME ?? 'app' },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: ['req.headers.authorization', 'body.password', 'body.token'],
});

export const createRequestLogger = (requestId: string) =>
  logger.child({ requestId });
```

### Environment Configuration
- **dotenv-safe** — not plain dotenv. Crashes loudly if required vars are missing.
- Single `config/index.ts` — never call `process.env.X` scattered through code
- All values typed — no string coercion at point of use

```typescript
import 'dotenv-safe/config';

function requireEnv(key: string): string {
  const value = process.env[key];
  if (!value) throw new Error(`Missing required env var: ${key}`);
  return value;
}

export const config = {
  server: {
    port:         parseInt(process.env.PORT ?? '3000', 10),
    nodeEnv:      process.env.NODE_ENV ?? 'development',
    isProduction: process.env.NODE_ENV === 'production',
  },
  database: { url: requireEnv('DATABASE_URL') },
  auth: {
    jwtSecret:       requireEnv('JWT_SECRET'),
    jwtAccessExpiry: process.env.JWT_ACCESS_EXPIRY ?? '15m',
    bcryptRounds:    parseInt(process.env.BCRYPT_ROUNDS ?? '12', 10),
  },
  redis:  { url: requireEnv('REDIS_URL') },
  sentry: { dsn: process.env.SENTRY_DSN ?? '' },
} as const;
```

### Authentication and Authorization
- **Passport.js** + **passport-jwt** for Express JWT auth strategies
- **jose** for raw JWT operations — signing, verifying, key rotation
- **bcryptjs** for password hashing — cost factor 12 minimum in production
- Access tokens: 15 minute expiry, RS256 (asymmetric) preferred over HS256
- Refresh tokens: 7 day expiry, stored `httpOnly; Secure; SameSite=Strict` cookie
- Never store any auth token in `localStorage` — XSS steals everything in localStorage
- Always verify authorization server-side — never trust client-supplied role claims
- Rotate refresh tokens on use — invalidate old token immediately after rotation

### Database (SQL)
- **Prisma** — ORM of choice. Schema-first, type-safe, migration-tracked.
- **PostgreSQL 15+** — production database. SQLite only for dev/test tooling.
- Every table has: `id` (cuid or UUID), `createdAt`, `updatedAt`
- Add `@@index` for every column in WHERE, ORDER BY, and foreign keys
- Cursor-based pagination only — offset pagination degrades at scale

```typescript
// Correct Prisma cursor pagination
async function getItems(cursor?: string, limit = 20) {
  return prisma.item.findMany({
    take:    limit,
    skip:    cursor ? 1 : 0,
    cursor:  cursor ? { id: cursor } : undefined,
    orderBy: { createdAt: 'desc' },
    where:   { deletedAt: null },
  });
}

// WRONG: unbounded query kills production
const users = await prisma.user.findMany(); // never — always add take
```

### Testing
- **Vitest** — preferred (ESM-native, faster than Jest, Jest-compatible API)
- **Supertest** — for HTTP integration tests
- **@testing-library/react** — for React component tests
- **msw (Mock Service Worker)** — for mocking API calls in frontend tests
- Coverage thresholds enforced — CI fails below minimum

```typescript
// vitest.config.ts
export default defineConfig({
  test: {
    globals: true,
    coverage: {
      provider: 'v8',
      thresholds: { lines: 70, branches: 60, functions: 70, statements: 70 },
      exclude: ['**/*.test.ts', '**/types/**', '**/config/**'],
    },
  },
});
```

### Error Monitoring
- **Sentry** — initialized before any route handlers, before other middleware
- Capture unhandled promise rejections and uncaught exceptions
- Tag every error with `requestId` for log correlation
- Never expose Sentry DSN in frontend source bundles

### HTTP Client
- **axios** with interceptors for server-to-server calls
- Always set explicit timeouts — never allow indefinite hanging
- Always handle network errors with typed `axios.isAxiosError()` check

```typescript
export const httpClient = axios.create({ timeout: 10_000 });

httpClient.interceptors.response.use(
  (res) => res,
  (err: unknown) => {
    if (axios.isAxiosError(err)) {
      logger.error('HTTP client error', { url: err.config?.url, status: err.response?.status });
    }
    return Promise.reject(err);
  }
);
```

### Process Management
- **PM2** in cluster mode — never run `node server.js` directly in production

```json
{
  "apps": [{
    "name": "api",
    "script": "dist/server.js",
    "instances": "max",
    "exec_mode": "cluster",
    "max_restarts": 10,
    "restart_delay": 5000
  }]
}
```

---

## PART 4 — PYTHON STACK

### Version and Environment
- **Python 3.11+** minimum — 3.12 preferred
- **pyenv** for version management
- **Poetry** — preferred for dependency management and virtual environments
- Always commit `pyproject.toml` with pinned versions
- Use `pip-compile` to generate locked `requirements.txt`
- Never `pip install` globally — always inside a virtual environment

### Web Framework
- **FastAPI** — required for all new AI and API projects
  - Async-native (ASGI), OpenAPI auto-generated, Pydantic-integrated, DI built in
- Always run with Gunicorn + uvicorn workers in production:

```bash
gunicorn app.main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --timeout 30
```

### Data Validation
- **Pydantic v2** — always. Requests, responses, config, data models.
- Use `model_config = ConfigDict(strict=True)` on all request schemas
- Never use bare `dict` or `Any` as a request body type

```python
from pydantic import BaseModel, Field, ConfigDict

class ChatRequest(BaseModel):
    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    message:         str      = Field(min_length=1, max_length=4000)
    conversation_id: str|None = Field(default=None, pattern=r'^[0-9a-f-]{36}$')
```

### Configuration
- **pydantic-settings** — typed, validated, fails loudly if required vars missing

```python
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

    database_url: str   # required — no default
    jwt_secret:   str   # required — no default
    redis_url:    str   # required — no default
    log_level:    str = 'INFO'
    env:          str = 'development'

    @property
    def is_production(self) -> bool:
        return self.env == 'production'

settings = Settings()  # crashes at startup if required vars missing
```

### Logging
- **structlog** with JSON renderer — structured, context-aware
- Never use `print()` in production paths
- Bind `request_id` to every log entry within a request context

```python
import structlog

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt='iso'),
        structlog.processors.JSONRenderer(),
    ],
)

logger = structlog.get_logger()
```

### Database
- **SQLAlchemy 2.0+** async with **Alembic** for migrations
- **asyncpg** for async PostgreSQL driver
- Always define indexes and constraints in the model
- Never write raw SQL strings

```python
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Index, func
from datetime import datetime
from uuid import uuid4

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = 'users'
    __table_args__ = (Index('ix_users_email', 'email'),)

    id:         Mapped[str]      = mapped_column(primary_key=True, default=lambda: str(uuid4()))
    email:      Mapped[str]      = mapped_column(unique=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())
```

### Testing
- **pytest** + **pytest-asyncio** + **httpx** (AsyncClient for FastAPI)
- **factory-boy** for test fixtures
- Coverage enforced: `pytest --cov=app --cov-fail-under=70`

---

## PART 5 — FRONTEND STACK

### Framework
- **React 18+** with TypeScript strict mode — default
- **Next.js 14+** (App Router) — when SSR, SSG, SEO, or full-stack needed
- **Vite 5+** — for SPAs. Fast, ESM-native.
- Never use Create React App — unmaintained since 2022

### State Management — Two Categories, Never Mixed

**Server state** (data from APIs) → **TanStack Query v5**
**Client state** (UI/preferences) → **Zustand**

```typescript
// TanStack Query — always handle all three states
function ItemList() {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['items'],
    queryFn:  api.getItems,
    staleTime: 30_000,
  });

  if (isLoading) return <LoadingSpinner />;
  if (isError)   return <ErrorMessage message={error.message} />;
  if (!data?.length) return <EmptyState />;
  return <ul>{data.map(i => <ItemRow key={i.id} item={i} />)}</ul>;
}
```

### Forms
- **React Hook Form** + **Zod resolver** — always

```typescript
const { register, handleSubmit, formState: { errors } } = useForm<FormData>({
  resolver: zodResolver(schema),
});
```

### Styling
- **Tailwind CSS v3+** — utility-first, purge-safe, no runtime cost
- **shadcn/ui** — accessible Radix UI components you own
- Never use CSS-in-JS (styled-components, emotion) for new projects

### API Client
- Single typed API client module with axios and interceptors
- Never call `fetch` or `axios` directly in components

```typescript
export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL,
  timeout: 10_000,
  withCredentials: true,
});
```

### Error Handling
- **React Error Boundary** on every route — one crash must not kill the app
- **sonner** — toast notifications on mutation success and failure
- Every async action has an error handler — no unhandled rejections

### Build Tooling
- **Vite** bundler
- **ESLint** + **Prettier** — configured, runs in CI
- **Husky** + **lint-staged** — pre-commit hooks for lint and format
- **TypeScript strict mode** — always

---

## PART 6 — INFRASTRUCTURE AND DEPLOYMENT

### Docker
- Every service has a `Dockerfile` using multi-stage builds
- Pin exact base image versions — never `node:latest`
- Always define `HEALTHCHECK`
- Never run as root inside a container

```dockerfile
FROM node:20.11-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20.11-alpine AS runner
WORKDIR /app
RUN addgroup -S app && adduser -S app -G app
COPY --from=builder --chown=app:app /app/dist ./dist
COPY --from=builder --chown=app:app /app/node_modules ./node_modules
USER app
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://localhost:3000/health || exit 1
CMD ["node", "dist/server.js"]
```

### Docker Compose (Local Dev)
- Always define healthchecks and `depends_on` with health conditions
- Never use `latest` image tags in compose files

### Reverse Proxy
- **Nginx** in front of every service in production
- Never expose app server ports directly to the internet
- SSL terminates at Nginx — apps speak HTTP internally

### CI/CD
Every pipeline runs in order — no stage skipped:

```
lint → typecheck → test → security audit → build → deploy
```

- Never merge to `main` without all stages passing
- Deploy only from CI — never manual deploys to production

---

## PART 7 — DATABASE STANDARDS

- **PostgreSQL 15+** — default for all new projects
- **Redis 7+** — caching, sessions, rate limiting, queues
- Every table: `id` (UUID), `created_at`, `updated_at`
- Soft deletes preferred: `deleted_at` nullable timestamp
- Add indexes on every foreign key and every WHERE/ORDER BY column
- Cursor-based pagination always — offset breaks past 1000 rows
- Define data retention policies before launch — tables never grow forever
- Test backup restores before go-live — an untested backup is not a backup

---

## PART 8 — API STANDARDS

### Versioning
- All routes versioned from day one: `/api/v1/...`

### Response Shape — Every Response, Every Time

```json
{ "success": true,  "data": {},    "requestId": "uuid" }
{ "success": false, "error": { "code": "ERR_CODE", "message": "..." }, "requestId": "uuid" }
{ "success": true,  "data": [],    "pagination": { "nextCursor": "x", "hasMore": true }, "requestId": "uuid" }
```

### HTTP Status Codes
| Code | When |
|------|------|
| 200  | Success |
| 201  | Resource created |
| 204  | Success, no content (DELETE) |
| 400  | Malformed request |
| 401  | Not authenticated |
| 403  | Not authorized |
| 404  | Not found |
| 422  | Validation failed |
| 429  | Rate limited |
| 500  | Unexpected server error |
| 503  | Service unavailable |

### Rate Limits
- All public endpoints: 60 req/min per IP
- Auth endpoints: 5 req/min per IP
- AI endpoints: 20 req/min per authenticated user
- Always return `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` headers

### Documentation
- OpenAPI 3.0 for every API
- FastAPI: auto-generated — every endpoint needs `summary`, `description`, `response_model`
- Express: `swagger-jsdoc` + `swagger-ui-express`

---

## PART 9 — SECURITY STANDARDS

### OWASP Top 10 Pre-Release Checklist
- [ ] All queries parameterized — no string SQL concatenation
- [ ] Passwords hashed with bcrypt, cost factor 12+
- [ ] All secrets in environment variables — none in code
- [ ] HTTPS only — HTTP redirects enforced at Nginx
- [ ] Security headers applied (see below)
- [ ] CORS allowlist explicit — never `*` in production
- [ ] All endpoints verify authorization server-side
- [ ] Debug mode disabled in production
- [ ] `npm audit` / `pip-audit` — no HIGH or CRITICAL findings
- [ ] All auth events and errors logged with requestId

### Required Security Headers
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; ...
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### JWT Standards
- RS256 (asymmetric) preferred over HS256 for distributed systems
- Access tokens: 15 minutes
- Refresh tokens: 7 days, `httpOnly; Secure; SameSite=Strict` cookie
- Rotate refresh tokens on every use
- Never store tokens in `localStorage`

---

## PART 10 — GIT WORKFLOW AND CODE REVIEW

### Branch Strategy
- `main` — production. Protected. Never push directly.
- `develop` — integration branch
- `feature/[ticket]-description` — from develop
- `fix/[ticket]-description` — bug fixes
- `hotfix/description` — urgent prod fixes from main

### Commit Conventions (Conventional Commits)
```
feat(auth): add refresh token rotation
fix(api): handle missing requestId in error responses
test(users): add integration tests for user creation
chore(deps): update Prisma to 5.8.0
```

### PR Requirements — All Must Pass Before Merge
- [ ] CI green (lint + typecheck + test + audit + build)
- [ ] At least one test added or updated
- [ ] No new ESLint or TypeScript errors
- [ ] Guardian audit clean
- [ ] Self-review against CLAUDE.md checklist complete

### Code Review — What Reviewers Check
- Does this follow STANDARDS.md approved stack?
- Are all errors handled — no silent catch blocks?
- Is logging structured with requestId?
- Is input validated with Zod/Pydantic?
- Are there tests covering new behavior?
- Would a developer unfamiliar with this code understand it in 5 minutes?

---

## PART 11 — OBSERVABILITY STANDARDS

### Health Check — Every Service
```json
{
  "status": "ok",
  "timestamp": "2025-01-01T00:00:00Z",
  "uptime": 3600,
  "version": "1.2.0",
  "dependencies": { "database": "ok", "redis": "ok" }
}
```

### Minimum Metrics (Every Production Service)
- Request rate per endpoint
- Error rate (5xx) per endpoint
- Response latency p50 / p95 / p99
- Database query latency
- Memory and CPU usage

### Log Correlation
Every log entry in a request chain shares the same `requestId`. This makes
tracing a single request through multiple services possible without a full
distributed tracing stack.

### Alerting Baseline
- Error rate > 1% over 5 minutes → alert
- p99 latency > 2 seconds → alert
- Health check failing > 30 seconds → alert
- Disk usage > 80% → alert

---

## QUICK REFERENCE — APPROVED STACK

| Need | Node / TypeScript | Python |
|------|------------------|--------|
| Language | TypeScript 5+ strict | Python 3.11+ |
| Web framework | Fastify 4 / Express + Helmet | FastAPI |
| Validation | Zod | Pydantic v2 |
| Logging | Pino | structlog |
| Config | dotenv-safe + config.ts | pydantic-settings |
| ORM | Prisma | SQLAlchemy 2 + Alembic |
| Auth | Passport.js + jose + bcryptjs | python-jose + passlib |
| Testing | Vitest + Supertest | pytest + httpx |
| Coverage | vitest --coverage (70%) | pytest --cov-fail-under=70 |
| Frontend data | TanStack Query v5 | — |
| Frontend forms | React Hook Form + Zod | — |
| Frontend state | Zustand | — |
| Frontend UI | shadcn/ui + Tailwind CSS | — |
| Bundler | Vite 5 | — |
| Error monitoring | Sentry | Sentry |
| Process management | PM2 cluster mode | Gunicorn + uvicorn workers |
| Task queue | BullMQ + Redis | Celery + Redis |
| HTTP client | axios | httpx |
| Package manager | pnpm / npm (pinned) | Poetry / pip-tools |

## WHAT CLAUDE MUST NEVER REACH FOR

| Junior Choice | Professional Standard | Why |
|---------------|----------------------|-----|
| `console.log` | Pino / structlog | Structured, observable, filterable |
| `Math.random()` for IDs | `crypto.randomUUID()` | Cryptographically secure |
| `localStorage` for tokens | `httpOnly` cookies | XSS steals localStorage silently |
| Hand-rolled validation | Zod / Pydantic | Type-safe, tested, maintained |
| Offset pagination | Cursor-based | Offset reads all prior rows at scale |
| `moment.js` | `date-fns` / `luxon` | Moment deprecated, 67kb bundle |
| `var` keyword | `const` / `let` | Function scoping causes subtle bugs |
| `any` TypeScript type | Typed or `unknown` | `any` disables TypeScript entirely |
| Create React App | Vite | CRA unmaintained since 2022 |
| Raw `useEffect` + `fetch` | TanStack Query | No caching, no dedup, no states |
| `useState` per form field | React Hook Form | Doesn't scale, re-renders on each keystroke |
| CSS-in-JS | Tailwind CSS | Runtime cost, larger bundles |
| `node:latest` Docker | `node:20.11-alpine` | Reproducible, minimal attack surface |
| Raw string SQL | ORM / parameterized queries | SQL injection vector |
| `node-fetch` | Native `fetch` (Node 18+) | Built-in since Node 18 |
| Redux (new project) | Zustand + TanStack Query | 80% less boilerplate |
| Promise without `.catch()` | Always handle rejections | Unhandled rejections crash Node |
| Empty `catch (e) {}` | Log + rethrow or typed response | Silent failures hide bugs forever |
| Manual `ALTER TABLE` | ORM migrations | Reproducible, versioned, reversible |
| Direct port exposure | Nginx reverse proxy | Security, SSL, rate limiting |
| HS256 JWT | RS256 JWT | Symmetric key compromise is total |
| SQLite in production | PostgreSQL | SQLite is not for concurrent production writes |

---

*OTLC Guardian · onthelevelconcepts.com · Built to the standard of a $100k engagement.*
