#!/usr/bin/env node
/* global process, console */
/**
 * Regenerate `openapi.json` from the backend, WITHOUT needing a running server
 * or a database.
 *
 * Strategy: build the backend Docker image (which has `app` importable) and run
 * `scripts/dump_openapi.py` inside it, which calls `app.openapi()` and prints the
 * schema to stdout. We capture stdout into `openapi.json`.
 *
 * Env vars:
 *   SKIP_BUILD=1   Reuse an existing image instead of rebuilding (CI can reuse
 *                  the image the docker job already built).
 *   IMAGE=<tag>    Image tag to build/run (default: revops-oapi).
 *
 * After this, run `pnpm codegen` to turn `openapi.json` into `src/api/schema.d.ts`.
 * `pnpm codegen:all` does both steps in sequence.
 */
import { spawnSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const frontendDir = resolve(__dirname, '..')
const repoRoot = resolve(frontendDir, '..', '..')
const image = process.env.IMAGE || 'revops-oapi'
const dumpScript = resolve(__dirname, 'dump_openapi.py')
const outFile = resolve(frontendDir, 'openapi.json')

function run(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, { stdio: 'inherit', cwd: repoRoot, ...opts })
  if (res.status !== 0) {
    console.error(`\n[gen-openapi] \`${cmd} ${args.join(' ')}\` failed (exit ${res.status}).`)
    process.exit(res.status || 1)
  }
  return res
}

if (process.env.SKIP_BUILD !== '1') {
  console.error(`[gen-openapi] Building backend image \`${image}\`...`)
  run('docker', ['build', '-f', 'packages/backend/Dockerfile', '-t', image, 'packages/backend'])
} else {
  console.error(`[gen-openapi] SKIP_BUILD=1 -> reusing existing image \`${image}\`.`)
}

console.error('[gen-openapi] Dumping OpenAPI schema from image...')
const res = spawnSync('docker', ['run', '--rm', '-i', image, 'python', '-'], {
  cwd: repoRoot,
  input: readFileSync(dumpScript),
  stdio: ['pipe', 'pipe', 'inherit'],
  maxBuffer: 64 * 1024 * 1024,
})
if (res.status !== 0) {
  console.error(`\n[gen-openapi] schema dump failed (exit ${res.status}).`)
  process.exit(res.status || 1)
}

writeFileSync(outFile, res.stdout)
console.error(`[gen-openapi] Wrote ${outFile} (${res.stdout.length} bytes).`)
