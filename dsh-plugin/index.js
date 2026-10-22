/**
 * dsh-code-quarantine-gate — DeepSeek-Harness gate for the
 * `dsh-code-quarantine` skill (mode A: intercept before the write lands).
 *
 * The harness has no Claude-Code-style PreToolUse hook; the equivalent seam is
 * the `tools/pre-execute` waterfall in `@deepseek-ai/dsh-tools`. This plugin
 * listens there, recognises every tool that is about to persist file content,
 * hands that content to the skill's Python scanner over its documented stdin
 * contract, and denies the call with the scanner's own evidence lines when a
 * CRITICAL finding is present.
 *
 * Design notes that matter:
 *  - The scanner is invoked as a subprocess, never imported: it stays the single
 *    source of truth and the plugin keeps no rules of its own.
 *  - A scanner crash must never wedge the host. Any failure other than a clean
 *    exit code 2 resolves to "allow", mirroring the skill's own fail-open
 *    contract for hook plumbing errors.
 *  - Only content-bearing mutations are inspected. A `dryRun` write, a read, or
 *    a non-file tool is left untouched, so the gate costs nothing on those.
 *
 * @module dsh-code-quarantine
 */
import { spawn } from 'node:child_process'
import { existsSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

/** Cordis plugin name used by loader diagnostics. */
export const name = 'dsh-code-quarantine'

/** Services this plugin reads. Declared so the loader mounts it after them. */
export const inject = ['tools']

const HERE = dirname(fileURLToPath(import.meta.url))

/**
 * Whether `path` names an existing directory.
 *
 * Used to validate the `target` the Client sends. A typo must surface as an error
 * the card can show; silently scanning the Host's own cwd instead would answer a
 * question nobody asked and paint the icon green.
 */
function isDirectory(path) {
  try {
    return statSync(path).isDirectory()
  } catch {
    return false
  }
}


/**
 * Tools whose `arguments` carry file content that will reach the disk.
 * Each entry maps a tool name to the function that extracts the prospective
 * writes as `[{ path, text, kind }]`, where `kind` is `write` (whole file) or
 * `fragment` (a slice spliced into an existing file).
 */
const WRITERS = new Map()

WRITERS.set('write', (args) => {
  const path = args?.file_path ?? args?.path
  const content = args?.content
  if (typeof path !== 'string' || typeof content !== 'string') return []
  return [{ path, text: content, kind: 'write' }]
})

WRITERS.set('ops_write_file', (args) => {
  if (args?.dryRun === true) return []
  const path = args?.path
  const content = args?.content
  if (typeof path !== 'string' || typeof content !== 'string') return []
  return [{ path, text: content, kind: 'write' }]
})

/** `edit` (official fs tool) and `ops_edit_file` share the edits-array shape. */
const editShaped = (args) => {
  if (args?.dryRun === true) return []
  const path = args?.file_path ?? args?.path
  if (typeof path !== 'string') return []
  const out = []
  if (typeof args?.old_string === 'string' || typeof args?.new_string === 'string') {
    out.push({ path, text: String(args?.new_string ?? ''), kind: 'fragment' })
  }
  if (Array.isArray(args?.edits)) {
    for (const edit of args.edits) {
      if (typeof edit?.newText === 'string') out.push({ path, text: edit.newText, kind: 'fragment' })
      else if (typeof edit?.new_string === 'string') out.push({ path, text: edit.new_string, kind: 'fragment' })
    }
  }
  return out.filter((entry) => entry.text.length > 0)
}

WRITERS.set('edit', editShaped)
WRITERS.set('ops_edit_file', editShaped)

/** `ops_replace` rewrites matches inside a file with a replacement template. */
WRITERS.set('ops_replace', (args) => {
  if (args?.dryRun === true) return []
  const path = args?.path
  const replacement = args?.replacement
  if (typeof path !== 'string' || typeof replacement !== 'string') return []
  return replacement.length > 0 ? [{ path, text: replacement, kind: 'fragment' }] : []
})

/**
 * Shell tools get their own pass: `curl … | bash` never touches a file write,
 * so it is invisible to the writers above.
 */
const SHELL_TOOLS = new Map()

SHELL_TOOLS.set('bash', (args) => commandOf(args))
SHELL_TOOLS.set('ops_bash', (args) => commandOf(args))
SHELL_TOOLS.set('pwsh', (args) => commandOf(args))

function commandOf(args) {
  for (const key of ['command', 'cmd', 'script']) {
    const value = args?.[key]
    if (typeof value === 'string' && value.trim()) return value
  }
  return ''
}

/**
 * Candidate roots for the scanner, most specific first.
 *
 * The bundle is installed as a package (``node_modules/dsh-code-quarantine``), so
 * this file's parent is ``node_modules`` — not the skill root. Resolving only
 * ``..`` used to make the gate inert the moment it was installed properly, while
 * working fine when run from a source checkout. Both layouts have to be tried.
 */
function skillRootCandidates(config) {
  const configured = config?.skillRoot
  if (typeof configured === 'string' && configured.trim()) {
    // An explicit path is a statement of intent: if it is wrong, say so. Silently
    // scanning with a *different* installation would hide the typo and, worse,
    // run the wrong rule set against the user's code.
    return [isAbsolute(configured) ? configured : resolve(process.cwd(), configured)]
  }
  const roots = []
  // Source checkout: this file lives at <repo>/dsh-plugin/index.js.
  roots.push(resolve(HERE, '..'))
  roots.push(HERE)
  // Installed layout: the bundle sits in a profile's node_modules while the
  // scanner lives in a skill directory. The skill is what ships the Python, so
  // every well-known skill root is a candidate.
  const homes = [process.env.DSH_HOME, join(homedir(), '.dsh')].filter(Boolean)
  for (const home of homes) {
    roots.push(join(home, 'skills', 'dsh-code-quarantine'))
    roots.push(join(home, 'skills', 'dsh-code-quarantine', 'dsh-plugin'))
  }
  roots.push(join(homedir(), '.claude', 'skills', 'dsh-code-quarantine'))
  roots.push(join(homedir(), '.workbuddy', 'skills', 'dsh-code-quarantine'))
  return roots
}

/** First candidate that actually contains the scanner. */
function resolveSkillRoot(config) {
  for (const root of skillRootCandidates(config)) {
    if (existsSync(join(root, 'scripts', 'quarantine.py'))) return root
  }
  return skillRootCandidates(config)[0]
}

/** Locate the scanner entry point, tolerating both layout guesses. */
function resolveHook(skillRoot, script) {
  const candidate = join(skillRoot, 'scripts', script)
  return existsSync(candidate) ? candidate : undefined
}

/**
 * Run one scanner invocation. Resolves to `{ blocked, output }`; a scanner that
 * fails for any reason other than exit code 2 resolves to allow.
 */
function runHook({ python, hookPath, payload, cwd, timeoutMs, env }) {
  return new Promise((resolveRun) => {
    let child
    try {
      child = spawn(python, [hookPath], {
        cwd,
        env,
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      })
    } catch {
      resolveRun({ blocked: false, output: '' })
      return
    }
    const chunks = []
    let settled = false
    const finish = (blocked, output) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolveRun({ blocked, output })
    }
    const timer = setTimeout(() => {
      try {
        child.kill()
      } catch {
        /* the child may already be gone */
      }
      finish(false, '')
    }, timeoutMs)
    timer.unref?.()
    child.stdout?.on('data', (chunk) => chunks.push(chunk))
    child.stderr?.on('data', (chunk) => chunks.push(chunk))
    child.on('error', () => finish(false, ''))
    child.on('close', (code) => {
      const output = Buffer.concat(chunks).toString('utf8').trim()
      finish(code === 2, output)
    })
    try {
      child.stdin?.on('error', () => {
        /* EPIPE when the child exits before reading; the close handler decides */
      })
      child.stdin?.end(JSON.stringify(payload), 'utf8')
    } catch {
      finish(false, '')
    }
  })
}

/** Route the Client half talks to for state and the arm/disarm switch. */
const RPC_PATH = '/dsh-code-quarantine/rpc'

/**
 * The bridge that gives the card the *whole* settings surface.
 *
 * The browser panel (`scripts/panel_server.py`) already knows how to read and
 * write rules, allowlists, exemptions and the AI block. Re-implementing that in
 * JavaScript would mean two copies of the same write logic drifting apart — a
 * rule disabled in one place still firing in the other. So the card calls the
 * same `Panel` object through this thin JSON-on-stdin shim.
 */
const BRIDGE_SCRIPT = 'panel_bridge.py'

/** Bridge calls that can legitimately take minutes (a full audit). */
const SLOW_BRIDGE = new Set(['scan', 'baseline', 'llm-test'])

/**
 * One bridge round-trip: JSON in on stdin, one JSON object out on stdout.
 *
 * The script is the only thing that knows how to touch the config files; this
 * function's whole job is transport, and every failure mode resolves to a
 * `{ ok: false, error }` object the card can render instead of a thrown error
 * that would blank the panel.
 */
function runBridge({ python, skillRoot, method, args, target, env, timeoutMs }) {
  const script = join(skillRoot, 'scripts', BRIDGE_SCRIPT)
  if (!existsSync(script)) {
    return Promise.resolve({ ok: false, error: `桥接脚本不存在: ${script}` })
  }
  return new Promise((resolveBridge) => {
    let child
    try {
      child = spawn(python, [script], {
        cwd: target,
        env,
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      })
    } catch (error) {
      resolveBridge({ ok: false, error: String(error) })
      return
    }
    const out = []
    let settled = false
    const finish = (value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolveBridge(value)
    }
    const ceiling = SLOW_BRIDGE.has(method) ? Math.max(timeoutMs * 40, 600000) : Math.max(timeoutMs * 4, 30000)
    const timer = setTimeout(() => {
      try {
        child.kill()
      } catch {
        /* already gone */
      }
      finish({ ok: false, error: '面板桥超时' })
    }, ceiling)
    timer.unref?.()
    child.stdout?.on('data', (chunk) => out.push(chunk))
    child.stderr?.on('data', () => {
      /* diagnostics only; stdout carries the answer */
    })
    child.on('error', (error) => finish({ ok: false, error: String(error) }))
    child.on('close', () => {
      const text = Buffer.concat(out).toString('utf8').trim()
      if (!text) {
        finish({ ok: false, error: '面板桥没有返回内容' })
        return
      }
      try {
        finish(JSON.parse(text))
      } catch {
        finish({ ok: false, error: `面板桥返回了非 JSON 内容: ${text.slice(0, 200)}` })
      }
    })
    try {
      child.stdin?.on('error', () => {
        /* EPIPE when the child exits early; close decides */
      })
      child.stdin?.end(JSON.stringify({ method, args: args || {}, target }), 'utf8')
    } catch (error) {
      finish({ ok: false, error: String(error) })
    }
  })
}

/**
 * Live gate state for one conversation, owned by the Host because the gate
 * lives here.
 *
 * The badge in the composer must report what actually happened on the last
 * inspection, not what the button believes it asked for: a coloured dot that
 * mirrors the button's own optimism is worse than no dot at all.
 *
 * One of these exists **per session**, not per process. Two windows on two
 * projects are two independent work streams: switching the gate off in one must
 * not silently disarm the other, and a BLOCK in one must not paint the other's
 * icon red. Sharing a single object made the switch act like a global mute
 * button, which is the opposite of what a per-workspace safety gate means.
 */
function createRuntime(config, sessionId = '') {
  return {
    /** The conversation this state belongs to; `''` is the fallback scope. */
    sessionId,
    /** Master switch, flipped from the card. */
    armed: true,
    /** `idle | scanning | clean | warn | block | error`. */
    phase: 'idle',
    /** Last verdict the scanner produced: `SAFE | REVIEW | BLOCK | ERROR`. */
    verdict: '',
    critical: 0,
    warning: 0,
    info: 0,
    /** File count from the last full audit, 0 when never run. */
    files: 0,
    lastRunAt: 0,
    lastMessage: '',
    /** Machine-readable reason the plugin cannot work, e.g. `scanner-missing`. */
    message: '',
    /**
     * Sticky worst result since the last reset: `'' | warn | block`.
     *
     * `phase` is momentary — a single successful write right after a block would
     * paint the icon green while the rejected content is still on the user's
     * clipboard. The icon therefore follows `alert`, which only rises by itself.
     */
    alert: '',
    blockOn: String(config?.blockOn || 'critical').toLowerCase(),
  }
}

/** Pull the scanner's own counters out of its report text. */
function parseCounts(output) {
  const read = (label) => {
    const match = new RegExp(`${label}\\s+(\\d+)`).exec(output || '')
    return match ? Number(match[1]) : 0
  }
  return { critical: read('CRITICAL'), warning: read('WARNING'), info: read('INFO') }
}

/**
 * Whether the request came from the page this Host is serving.
 *
 * The route sits on the same origin as the GUI, so a browser sends `Origin`
 * only for cross-origin attempts; a mismatch is exactly what a malicious page
 * embedding this port would produce.
 */
function isSameOrigin(request) {
  const origin = request?.headers?.origin
  if (!origin) return true
  try {
    return new URL(origin).host === request.headers.host
  } catch {
    return false
  }
}

function readJsonBody(request, limit = 64 * 1024) {
  return new Promise((resolveBody) => {
    const chunks = []
    let size = 0
    request.on('data', (chunk) => {
      size += chunk.length
      if (size > limit) {
        resolveBody({ __tooLarge: true })
        request.destroy()
        return
      }
      chunks.push(chunk)
    })
    request.on('end', () => {
      try {
        resolveBody(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'))
      } catch {
        resolveBody(null)
      }
    })
    request.on('error', () => resolveBody(null))
  })
}

function writeJson(response, status, body) {
  const payload = JSON.stringify(body)
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(payload),
  })
  response.end(payload)
}

/**
 * Run one full audit and read the verdict back out of the text report.
 *
 * The CLI is the same entry point a human would run, so the badge and the
 * terminal never disagree about what "clean" means.
 */
function runScan({ target, python, skillRoot, timeoutMs, env, blockOn }) {
  const cli = join(skillRoot, 'scripts', 'quarantine.py')
  const empty = { verdict: 'ERROR', files: 0, critical: 0, warning: 0, info: 0, message: '扫描器不存在' }
  if (!existsSync(cli)) return Promise.resolve(empty)
  return new Promise((resolveScan) => {
    let child
    try {
      child = spawn(python, [cli, target, '--full', '--no-color'], {
        cwd: target,
        env: { ...env, DSH_QUARANTINE_BLOCK_ON: blockOn },
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      })
    } catch (error) {
      resolveScan({ ...empty, message: String(error) })
      return
    }
    const chunks = []
    let settled = false
    const finish = (value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolveScan(value)
    }
    // A full audit on a large tree legitimately takes minutes; the per-write
    // timeout is far too tight here, so the ceiling is its own number.
    const timer = setTimeout(() => {
      try {
        child.kill()
      } catch {
        /* already gone */
      }
      finish({ ...empty, message: '全量审计超时' })
    }, Math.max(timeoutMs * 40, 600000))
    timer.unref?.()
    child.stdout?.on('data', (chunk) => chunks.push(chunk))
    child.stderr?.on('data', (chunk) => chunks.push(chunk))
    child.on('error', (error) => finish({ ...empty, message: String(error) }))
    child.on('close', (code) => {
      const output = Buffer.concat(chunks).toString('utf8')
      const counts = parseCounts(output)
      const verdictLine = /VERDICT:\s*([A-Z]+)/.exec(output)
      const filesLine = /(\d+)\s+files/.exec(output)
      const verdict = verdictLine ? verdictLine[1] : code === 3 ? 'ERROR' : code === 2 ? 'BLOCK' : 'SAFE'
      const errorLine = /^ERROR:\s*(.+)$/m.exec(output)
      finish({
        verdict,
        files: filesLine ? Number(filesLine[1]) : 0,
        ...counts,
        message: errorLine ? errorLine[1].trim() : verdict,
      })
    })
  })
}

/** Cordis entry point. */
export function apply(ctx, config = {}) {
  const enabled = config.enabled !== false
  if (!enabled) return

  const skillRoot = resolveSkillRoot(config)
  const python = config.python || (process.platform === 'win32' ? 'python' : 'python3')
  const timeoutMs = Number(config.timeoutMs) > 0 ? Number(config.timeoutMs) : 15000
  const blockOn = String(config.blockOn || 'critical').toLowerCase()
  const writeHook = resolveHook(skillRoot, 'hook_pre_write.py')
  const shellHook = resolveHook(skillRoot, 'hook_shell.py')
  const scannerReady = Boolean(writeHook || shellHook)

  // A missing scanner must not silently disable the whole plugin: the composer
  // button would still render, but every request behind it would 404 and the
  // user would see a dead control with no explanation. Report the problem
  // through the same channel the card reads, and keep the route alive.
  if (!scannerReady) {
    ctx.logger?.warn?.(
      'dsh-code-quarantine: no scanner found under %s; the gate is inert',
      skillRoot,
    )
  }

  // Base environment for every scanner invocation. `DSH_QUARANTINE_BLOCK_ON`
  // is deliberately *not* baked in here: the threshold is per conversation
  // (`configure`), so it is added by `envFor` at call time. Baking it in made a
  // change in one window retune the gate for every other window.
  const baseEnv = {
    ...process.env,
    PYTHONUTF8: '1',
    PYTHONIOENCODING: 'utf-8',
  }

  /** Environment for one conversation's scanner run. */
  const envFor = (runtime) => ({ ...baseEnv, DSH_QUARANTINE_BLOCK_ON: runtime.blockOn })

  const runtimes = new Map()
  const listeners = new Set()
  const publish = () => {
    for (const listener of listeners) {
      try {
        listener()
      } catch {
        /* a dead subscriber must not break the gate */
      }
    }
  }

  /**
   * The state object for one conversation.
   *
   * Created on first use so a session that never touches the gate costs nothing,
   * and keyed by the session id rather than by the workspace path: two windows
   * can legitimately be open on the same project while the user tests something
   * destructive in one of them, and those two must not share a switch.
   */
  const runtimeFor = (sessionId) => {
    const key = typeof sessionId === 'string' && sessionId ? sessionId : ''
    let runtime = runtimes.get(key)
    if (!runtime) {
      runtime = createRuntime(config, key)
      if (!scannerReady) {
        runtime.phase = 'error'
        runtime.message = 'scanner-missing'
        runtime.lastMessage = skillRoot
      }
      runtimes.set(key, runtime)
    }
    return runtime
  }

  const setPhase = (runtime, phase, extra) => {
    runtime.phase = phase
    if (extra) Object.assign(runtime, extra)
    runtime.lastRunAt = Date.now()
    publish()
  }

  /**
   * Record a verdict that the icon must keep showing.
   *
   * `phase` is momentary — the next successful write would overwrite a BLOCK
   * with CLEAN within seconds, so the indicator would flash red once and then
   * claim everything is fine while the rejected content is still sitting in the
   * user's clipboard. `alert` is the sticky half: it only ever rises on its own,
   * and only an explicit action (a full audit that comes back clean, or the
   * card's reset) lowers it.
   */
  const raiseAlert = (runtime, level) => {
    const rank = { '': 0, warn: 1, block: 2 }
    if (rank[level] > rank[runtime.alert]) runtime.alert = level
  }

  const inspect = async (runtime, hookPath, payload, cwd, kind) => {
    if (!hookPath) return { blocked: false, output: '' }
    runtime.phase = 'scanning'
    publish()
    const result = await runHook({ python, hookPath, payload, cwd, timeoutMs, env: envFor(runtime) })
    const counts = parseCounts(result.output)
    if (result.blocked) {
      runtime.verdict = 'BLOCK'
      raiseAlert(runtime, 'block')
      setPhase(runtime, 'block', { ...counts, lastMessage: result.output.split('\n')[0] || '' })
    } else if (counts.critical || counts.warning) {
      // The scanner ran and found something below the block threshold; the
      // badge stays amber so a WARNING-only pass is not reported as clean.
      runtime.verdict = counts.critical ? 'BLOCK' : 'REVIEW'
      raiseAlert(runtime, counts.critical ? 'block' : 'warn')
      setPhase(runtime, 'warn', { ...counts, lastMessage: result.output.split('\n')[0] || '' })
    } else {
      runtime.verdict = 'SAFE'
      // Keep the last incident's counters while an alert is pending: showing
      // "C 0 / W 0" next to a red icon reads like a contradiction. They are
      // cleared together with the alert, by `reset` or a clean full audit.
      const keep = runtime.alert ? { critical: runtime.critical, warning: runtime.warning, info: runtime.info } : counts
      setPhase(runtime, 'clean', keep)
    }
    return result
  }

  /**
   * Which conversation is making this tool call.
   *
   * `exec.agent` is the caller set by the agent loop; its `session.id` is the
   * durable identity of the window the user is working in. Anything else (a
   * subagent without a session, an older harness) falls back to `''`, which is a
   * single shared scope — degraded, but never wrong in a way that blocks work.
   */
  const sessionOf = (exec) => {
    try {
      const session = exec?.agent?.session
      const id = session && session.id
      return typeof id === 'string' ? id : ''
    } catch {
      return ''
    }
  }

  ctx.on('tools/pre-execute', async (exec, next) => {
    const toolName = String(exec?.name ?? '')
    const args = exec?.arguments
    const cwd = process.cwd()
    const runtime = runtimeFor(sessionOf(exec))

    if (!runtime.armed) return next()

    try {
      const writer = WRITERS.get(toolName)
      if (writer) {
        const edits = writer(args)
        if (!edits.length) return next()
        const payload = {
          hook_event_name: 'PreToolUse',
          tool_name: toolName,
          cwd,
          tool_input: {
            file_path: edits[0].path,
            ...(edits.length === 1 && edits[0].kind === 'write' ? { content: edits[0].text } : {}),
            ...(edits.length === 1 && edits[0].kind === 'fragment' ? { new_string: edits[0].text } : {}),
            ...(edits.length > 1 ? { edits: edits.map((e) => ({ new_string: e.text })) } : {}),
          },
        }
        const result = await inspect(runtime, writeHook, payload, cwd, 'write')
        if (result.blocked) return deny(result.output, 'write')
        return next()
      }

      const shellReader = SHELL_TOOLS.get(toolName)
      if (shellReader) {
        const command = shellReader(args)
        if (!command) return next()
        const payload = {
          hook_event_name: 'PreToolUse',
          tool_name: toolName,
          cwd,
          tool_input: { command },
        }
        const result = await inspect(runtime, shellHook, payload, cwd, 'shell')
        if (result.blocked) return deny(result.output, 'shell')
        return next()
      }
    } catch (error) {
      // The gate is advisory plumbing: never fail the call because it broke.
      ctx.logger?.warn?.('dsh-code-quarantine: %s', String(error))
      setPhase(runtime, 'error', { lastMessage: String(error) })
    }
    return next()
  })

  /**
   * The card's transport. Registered only when a browser server exists, so the
   * gate still works in a headless profile where the Client half never loads.
   */
  const registerRoute = () => {
    const webServer = typeof ctx.get === 'function' ? ctx.get('webServer') : undefined
    if (!webServer || typeof webServer.register !== 'function') return () => {}
    return webServer.register({
      kind: 'exact',
      path: RPC_PATH,
      handler: async (request, response) => {
        if (!isSameOrigin(request)) {
          writeJson(response, 403, { ok: false, code: 'FORBIDDEN_ORIGIN' })
          return
        }
        const body = request.method === 'POST' ? await readJsonBody(request) : {}
        if (body && body.__tooLarge) {
          writeJson(response, 413, { ok: false, code: 'BODY_TOO_LARGE' })
          return
        }
        const method = String(body?.method || 'state')
        // The Client sends `{ method, args }`; older shapes passed the fields at
        // the top level. Accept both so a stale cached bundle cannot silently
        // turn `arm` into a no-op.
        const args = body && typeof body.args === 'object' && body.args ? body.args : body || {}
        // Which conversation is asking. The card always sends its own session; a
        // bare `curl` from a terminal sends none and lands in the shared `''`
        // scope, which is also what a single-window user gets in practice.
        const sessionId = typeof body?.sessionId === 'string' ? body.sessionId : typeof args.sessionId === 'string' ? args.sessionId : ''
        const runtime = runtimeFor(sessionId)
        try {
          if (method === 'state') {
            writeJson(response, 200, { ok: true, state: { ...runtime } })
            return
          }
          if (method === 'arm') {
            runtime.armed = args.armed !== false
            if (!runtime.armed) runtime.phase = 'disarmed'
            else if (runtime.phase === 'disarmed') runtime.phase = 'idle'
            publish()
            writeJson(response, 200, { ok: true, state: { ...runtime } })
            return
          }
          if (method === 'configure') {
            const next = String(args.blockOn || '').toLowerCase()
            if (next === 'critical' || next === 'warning') {
              // Only this conversation's threshold. `envFor(runtime)` builds the
              // scanner environment per call, so there is no shared env object to
              // mutate — mutating one would retune every other window.
              runtime.blockOn = next
              publish()
            }
            writeJson(response, 200, { ok: true, state: { ...runtime } })
            return
          }
          if (method === 'audit') {
            if (!scannerReady) {
              writeJson(response, 200, { ok: false, code: 'NO_SCANNER', state: { ...runtime } })
              return
            }
            const requested = typeof args.target === 'string' ? args.target.trim() : ''
            // The Client sends the Session's workspace. Reject a target that is not
            // an existing absolute directory instead of falling back to
            // `process.cwd()`: the Host's own cwd is the profile directory, so a
            // silent fallback audits `~/.dsh/profiles/<name>` and cheerfully
            // reports six unrelated files as clean.
            if (requested && !isAbsolute(requested)) {
              writeJson(response, 400, { ok: false, code: 'TARGET_NOT_ABSOLUTE', target: requested })
              return
            }
            if (requested && !isDirectory(requested)) {
              writeJson(response, 400, { ok: false, code: 'TARGET_MISSING', target: requested })
              return
            }
            const target = requested || process.cwd()
            const result = await runScan({ target, python, skillRoot, timeoutMs, env: envFor(runtime), blockOn: runtime.blockOn })
            runtime.files = result.files
            runtime.verdict = result.verdict
            // `runScan` returns flat counters (`{critical, warning, info}`), not a
            // nested `counts` object. Spreading the missing field silently left the
            // previous incident's numbers on screen after a fresh audit.
            const counts = { critical: result.critical, warning: result.warning, info: result.info }
            if (result.verdict === 'ERROR') {
              setPhase(runtime, 'error', { ...counts, lastMessage: result.message })
            } else if (result.verdict === 'BLOCK') {
              raiseAlert(runtime, 'block')
              setPhase(runtime, 'block', { ...counts, lastMessage: result.message })
            } else if (result.verdict === 'REVIEW') {
              raiseAlert(runtime, 'warn')
              setPhase(runtime, 'warn', { ...counts, lastMessage: result.message })
            } else {
              // A full audit is the one thing that may lower the sticky alert:
              // the user asked for a whole-project answer, and it came back clean.
              runtime.alert = ''
              setPhase(runtime, 'clean', { ...counts, lastMessage: result.message })
            }
            writeJson(response, 200, { ok: true, state: { ...runtime } })
            return
          }
          if (method === 'reset') {
            // Clears the sticky alert without touching the arm switch: the user
            // has seen the red icon and is done with that incident.
            runtime.alert = ''
            runtime.verdict = ''
            runtime.phase = runtime.armed ? 'idle' : 'disarmed'
            runtime.critical = 0
            runtime.warning = 0
            runtime.info = 0
            runtime.lastMessage = ''
            runtime.lastRunAt = Date.now()
            publish()
            writeJson(response, 200, { ok: true, state: { ...runtime } })
            return
          }
          if (method === 'panel') {
            // Everything the browser panel can do, forwarded verbatim to the
            // Python `Panel` object. The card must not grow a second copy of the
            // config writers: a rule toggled in one surface has to be the same
            // rule the scanner reads.
            const op = String(args.op || '')
            if (!op) {
              writeJson(response, 400, { ok: false, code: 'MISSING_OP' })
              return
            }
            const requested = typeof args.target === 'string' ? args.target.trim() : ''
            // The Client sends the Session's workspace. Reject a target that is not
            // an existing absolute directory instead of falling back to
            // `process.cwd()`: the Host's own cwd is the profile directory, so a
            // silent fallback audits `~/.dsh/profiles/<name>` and cheerfully
            // reports six unrelated files as clean.
            if (requested && !isAbsolute(requested)) {
              writeJson(response, 400, { ok: false, code: 'TARGET_NOT_ABSOLUTE', target: requested })
              return
            }
            if (requested && !isDirectory(requested)) {
              writeJson(response, 400, { ok: false, code: 'TARGET_MISSING', target: requested })
              return
            }
            const target = requested || process.cwd()
            const payload = args.args && typeof args.args === 'object' ? args.args : {}
            // The bridge methods that take a directory (`scan`, `state`, `save`,
            // `baseline`, ...) read it from the payload, not from the envelope. A
            // nested target must clear the same bar as the top-level one: otherwise
            // the guard above is decoration and a caller reaches the same
            // "audit the Host's own cwd" outcome by moving the field one level down.
            const nested = typeof payload.target === 'string' ? payload.target.trim() : ''
            if (nested) {
              if (!isAbsolute(nested)) {
                writeJson(response, 400, { ok: false, code: 'TARGET_NOT_ABSOLUTE', target: nested })
                return
              }
              if (!isDirectory(nested)) {
                writeJson(response, 400, { ok: false, code: 'TARGET_MISSING', target: nested })
                return
              }
            }
            const result = await runBridge({
              python,
              skillRoot,
              method: op,
              args: payload,
              target,
              env: envFor(runtime),
              timeoutMs,
            })
            // A scan through the bridge is also a scan as far as the badge is
            // concerned: the icon must not keep saying "clean" while the card is
            // showing a table full of findings.
            if (op === 'scan' && result.ok && result.data) {
              const summary = result.data.summary || {}
              const sev = summary.severity || {}
              const counts = {
                critical: Number(sev.CRITICAL || 0),
                warning: Number(sev.WARNING || 0),
                info: Number(sev.INFO || 0),
              }
              runtime.files = Number(summary.scanned_files || 0)
              runtime.verdict = String(result.data.verdict || '')
              if (counts.critical) {
                raiseAlert(runtime, 'block')
                setPhase(runtime, 'block', { ...counts })
              } else if (counts.warning) {
                raiseAlert(runtime, 'warn')
                setPhase(runtime, 'warn', { ...counts })
              } else {
                runtime.alert = ''
                setPhase(runtime, 'clean', { ...counts })
              }
              result.state = { ...runtime }
            }
            writeJson(response, 200, result)
            return
          }
          writeJson(response, 404, { ok: false, code: 'UNKNOWN_METHOD', method })
        } catch (error) {
          writeJson(response, 500, { ok: false, code: 'HANDLER_FAILED', message: String(error) })
        }
      },
    })
  }

  if (typeof ctx.inject === 'function') {
    ctx.inject(['webServer'], (hostCtx) => hostCtx.effect(() => registerRoute(), 'dsh-code-quarantine: rpc'))
  } else {
    ctx.effect(() => registerRoute(), 'dsh-code-quarantine: rpc')
  }

  ctx.logger?.info?.(
    'dsh-code-quarantine: guarding %d write tools and %d shell tools (blockOn=%s)',
    WRITERS.size,
    SHELL_TOOLS.size,
    blockOn,
  )
}

/**
 * Whether the scanner's own output already tells the model what to do next.
 * Both hook scripts print a remediation line, so appending ours would repeat the
 * same advice twice in the denial the model reads.
 */
function hasOwnRemediation(report) {
  return report.includes('校验') || report.includes('.dsh-quarantine-ignore')
}

/** Build the denial the model sees: the scanner's report plus a next action. */
function deny(output, kind) {
  const report = output || '[dsh-code-quarantine] CRITICAL 命中，已拦截'
  if (hasOwnRemediation(report)) return { kind: 'deny', reason: report }
  const tail =
    kind === 'shell'
      ? '该命令会下载并立即执行远端内容。请改为先下载到本地、审阅、校验哈希后再执行。'
      : '请先修复上述 CRITICAL 问题再写入。若确认是误报，在项目根目录的 .dsh-quarantine-ignore 中按 rule_id + 路径登记豁免。'
  return { kind: 'deny', reason: `${report}\n\n${tail}` }
}

export default { name, inject, apply }
