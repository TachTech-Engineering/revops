# Frontend (Panther Dashboard)

React + Redux Toolkit (RTK Query) client for the Panther Dashboard API.

## OpenAPI-driven types (`src/api/schema.d.ts`)

`src/api/schema.d.ts` is **generated** from the backend's OpenAPI schema by
[`openapi-typescript`](https://github.com/openapi-ts/openapi-typescript) and is
**committed** to the repo. It exists so the frontend's request/response types
can be tied to the backend's Pydantic models instead of hand-written interfaces
that silently drift out of sync.

Consume generated types like this:

```ts
import type { components } from './schema'
type UserRoleResponse = components['schemas']['UserRoleResponse']
```

The role endpoints in `src/api/pantherApi.ts` already source their types this
way as a reference for how to adopt more.

### Regenerating

```bash
# 1) dump the backend schema + 2) regenerate schema.d.ts, in one step
pnpm codegen:all
```

Under the hood:

- `pnpm openapi:dump` builds the backend Docker image and runs
  `scripts/dump_openapi.py` inside it, which calls `app.openapi()` (no database
  or running server needed) and writes `openapi.json`.
- `pnpm codegen` runs `openapi-typescript openapi.json -o src/api/schema.d.ts`.

`openapi.json` is an intermediate artifact and is git-ignored; only
`schema.d.ts` is committed.

> Note: `scripts/dump_openapi.py` contains a small shim that resolves one
> stringized `response_model` forward-ref in the backend (`escalation.py`) so
> `app.openapi()` doesn't raise under the pinned FastAPI/Pydantic v2 stack. It
> does not modify backend source and becomes a no-op if the backend drops the
> quotes.

### Drift check (CI)

The `Frontend (OpenAPI schema drift)` job in `.github/workflows/ci.yml`
regenerates `schema.d.ts` from the backend on every push/PR and runs
`git diff --exit-code` against the committed file. **If a backend API change
isn't reflected in the committed `schema.d.ts`, CI fails.** To fix, run
`pnpm codegen:all` and commit the result.

Tradeoff: the drift job builds the backend image so it can dump the schema
offline (no DB). That adds one backend image build to CI; in exchange the check
needs no live server, database, or network to the API.
