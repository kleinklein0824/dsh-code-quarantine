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
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { dirname, isAbsolute, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

/** Cordis plugin name used by loader diagnostics. */
export const name = 'dsh-code-quarantine'

/** Services this plugin reads. Declared so the loader mounts it after them. */
export const inject = ['tools']

const HERE = dirname(fileURLToPath(import.meta.url))

/**
 * The user-facing master switch lives in one file for the whole installation,
 * not in each conversation's state. "Do I want this tool at all?" is a question
 * about the person, not about the project they happen to have open; a per-session
 * master would have to be flipped again in every window.
 */
const SETTINGS_NAME = 'dsh-code-quarantine.settings.json'

/** Files whose edits mean an open card is rendering stale configuration. */
const PROJECT_CONFIG = '.dsh-quarantine.yml'
const IGNORE_FILE = '.dsh-quarantine-ignore'
/** Append-only repair trail; a write from either surface must reach both. */
const HISTORY_FILE = '.dsh-quarantine-history.jsonl'

/** How often to notice an external config edit (the browser panel uses 2s too). */
const CONFIG_WATCH_MS = 2000

/**
 * How many inspected writes one conversation keeps in its live trail.
 *
 * The trail is what the card renders while the conversation is running, so it
 * has to be bounded: an agent that writes a hundred files would otherwise grow
 * this array for the lifetime of the window. Old entries are dropped from the
 * front — the card only ever shows the newest ones.
 */
const LIVE_LOG_LIMIT = 200

/** How many live entries the card shows at once. */
const LIVE_SHOW_LIMIT = 40

/** Where the master switch is persisted. `settingsPath` exists for tests. */
function settingsPathOf(config) {
  const configured = config?.settingsPath
  if (typeof configured === 'string' && configured.trim()) {
    return isAbsolute(configured) ? configured : resolve(process.cwd(), configured)
  }
  return join(process.env.DSH_HOME || join(homedir(), '.dsh'), SETTINGS_NAME)
}

/** `undefined` means "no preference recorded yet"; the caller picks the default. */
function readSettingEnabled(path) {
  try {
    const data = JSON.parse(readFileSync(path, 'utf8'))
    return data && typeof data.enabled === 'boolean' ? data.enabled : undefined
  } catch {
    return undefined
  }
}

/** Persist the master switch. A failed write must not make the toggle lie. */
function writeSettingEnabled(path, enabled, logger) {
  try {
    mkdirSync(dirname(path), { recursive: true })
    const temp = `${path}.${process.pid}.tmp`
    writeFileSync(temp, `${JSON.stringify({ enabled }, null, 2)}\n`, 'utf8')
    renameSync(temp, path)
    return true
  } catch (error) {
    logger?.warn?.('dsh-code-quarantine: could not persist the master switch: %s', String(error))
    return false
  }
}


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
/**
 * Run one hook and return its verdict, its human report, and its machine report.
 *
 * The hook is deliberately quiet on stderr when it lets a call through — the
 * host renders any non-empty hook stderr as a red `Error:` line, so reporting an
 * allowed WARNING there makes a normal write look broken. But this plugin still
 * needs those counts: a WARNING-only pass is what turns the icon amber.
 *
 * So the hook writes a JSON line to the file named by `DSH_QUARANTINE_REPORT_FILE`
 * and this function reads it back. Two channels, two audiences: the transcript
 * stays clean, the badge stays truthful.
 */
function runHook({ python, hookPath, payload, cwd, timeoutMs, env, reportPath }) {
  return new Promise((resolveRun) => {
    let child
    try {
      child = spawn(python, [hookPath], {
        cwd,
        env: reportPath ? { ...env, DSH_QUARANTINE_REPORT_FILE: reportPath } : env,
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      })
    } catch {
      resolveRun({ blocked: false, output: '', report: null })
      return
    }
    const chunks = []
    let settled = false
    const finish = (blocked, output) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolveRun({ blocked, output, report: readReport(reportPath) })
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

/**
 * Read back the last machine report the hook wrote, if any.
 *
 * One line per inspected file, so the last line is the one that decided this
 * call's verdict — a single write can touch several files and only the last one
 * is what the exit code reflects.
 */
function readReport(reportPath) {
  if (!reportPath) return null
  try {
    const text = readFileSync(reportPath, 'utf8').trim()
    if (!text) return null
    const lines = text.split('\n')
    return JSON.parse(lines[lines.length - 1])
  } catch {
    return null
  } finally {
    try {
      rmSync(reportPath, { force: true })
    } catch {
      /* the OS will clean the temp dir eventually */
    }
  }
}

/** Route the Client half talks to for state and the arm/disarm switch. */
const RPC_PATH = '/dsh-code-quarantine/rpc'

/**
 * Server-sent events: the card's live feed.
 *
 * The card used to poll this route every 1.5s while open and every 6s while
 * closed. Polling is not "real time" — a block that happens right after a tick
 * shows up a second and a half later, and the gap is invisible: the icon simply
 * looks calm. Worse, the closed-state poll runs forever, so an idle window keeps
 * asking a question whose answer has not changed.
 *
 * `WebRoute.handler` owns the whole response lifecycle, so holding it open for a
 * stream is exactly what the route type is for. Every state change already goes
 * through `publish()`; this turns that fan-out into a push.
 */
const EVENT_PATH = '/dsh-code-quarantine/events'

/** How often to write a comment line so proxies and the OS keep the socket. */
const EVENT_HEARTBEAT_MS = 25000

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
    /** The workspace the card (or the session that created this state) points at. */
    target: '',
    /** Master switch, flipped from the card. */
    armed: true,
    /** Whether the session-created audit has already been started for this session. */
    autoScanned: false,
    /** `idle | scanning | clean | warn | block | error`. */
    phase: 'idle',
    /** Last verdict the scanner produced: `SAFE | REVIEW | BLOCK | ERROR`. */
    verdict: '',
    critical: 0,
    warning: 0,
    info: 0,
    /** File count from the last full audit, 0 when never run. */
    files: 0,
    /**
     * Bumped when a scan result is cached for the card to fetch.
     *
     * The automatic session audit produces the same full result the scan tab
     * renders. Putting that array on the state frame would send every finding to
     * every part of the card on every unrelated state change; a counter plus a
     * `scan-result` read lets the tab ask only when it needs the table.
     */
    scanRev: 0,
    /**
     * Live monitoring, per conversation.
     *
     * The session-created audit answers "what is in this project *now*", but the
     * question the user actually asks while working is "is what the agent is
     * writing right now clean?" — and that answer has to appear without pressing
     * a button. `liveLog` is that answer: one entry per inspected write, appended
     * by `inspect()` and pushed on the state frame by revision.
     *
     * `liveRev` is the counter the card watches. The entries themselves stay off
     * the frame (they carry file paths and messages); a `live-log` read fetches
     * them, exactly like `scan-result` does for the audit table.
     */
    liveRev: 0,
    /** Files inspected live since this conversation started watching. */
    liveChecked: 0,
    /** Of those, how many produced at least one finding. */
    liveHits: 0,
    /** Bounded ring of the newest live entries, oldest first. */
    liveLog: [],
    /** When live monitoring started for this conversation; 0 = not yet. */
    liveSince: 0,
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
    /**
     * Bumped every time the repair trail grows.
     *
     * The history tab shows write-time snapshots plus a status that is a claim
     * about the file *now*. Pushing a counter is enough for the card to know it
     * should re-read; sending the entries themselves would put the JSONL on the
     * state frame that every other part of the card also listens to.
     */
    historyRev: 0,
    /**
     * Bumped when a config write lands through this plugin (rules, allowlists,
     * exemptions, AI endpoint).
     *
     * The card's forms are read once on open, which is right for a form the user
     * is filling in — re-reading under their cursor would erase typing. But the
     * *other* surface can write the same files, so an open card needs a hint that
     * what it is showing is now out of date. This counter is that hint.
     */
    configRev: 0,
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
 * Counts from the hook's machine report, falling back to scraping its stderr.
 *
 * The report is authoritative: the hook only prints to stderr when it blocks, so
 * an allowed WARNING leaves nothing to scrape. The fallback exists for a hook
 * that is older than `DSH_QUARANTINE_REPORT_FILE` — a stale skill install should
 * degrade to "counts only when blocked", not to "never reports anything".
 */
function countsOf(result) {
  const report = result?.report
  if (report && report.counts && typeof report.counts === 'object') {
    const pick = (key) => Number(report.counts[key] || 0)
    return { critical: pick('CRITICAL'), warning: pick('WARNING'), info: pick('INFO') }
  }
  return parseCounts(result?.output)
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

  // Master switch: one persisted preference for the whole installation. It is
  // deliberately separate from `config.enabled`, which is an install-level kill
  // switch in the profile patch: a user who wants the icon and settings surface
  // but no automatic behaviour must not have to edit YAML and restart.
  const settingsPath = settingsPathOf(config)
  const storedEnabled = readSettingEnabled(settingsPath)
  const settings = { enabled: storedEnabled === undefined ? true : storedEnabled }

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

  /**
   * The last automatic audit's full result, per conversation.
   *
   * The card's scan table needs the findings array, but the live state frame is
   * sent on every icon change and must stay small. Keeping the JSON here and
   * exposing it through `scan-result` means the table can be populated without
   * re-running a scan and without bloating every frame.
   */
  const scanCache = new Map()

  /**
   * Open SSE responses, keyed by the session they belong to.
   *
   * One entry per connected card. `publish` walks them and writes the *owning
   * session's* state to each, so two windows never see each other's verdict —
   * a broadcast of one shared object would leak the other window's block into
   * this window's icon.
   */
  const streams = new Set()

  /**
   * Push one conversation's state to the feeds that asked for it.
   *
   * Scoped by session on purpose. Broadcasting every change to every feed looks
   * harmless — each frame carries a whole state object, so a client could
   * overwrite its own with a stranger's. That is exactly the bug: window B would
   * repaint from window A's frame and show A's block. A feed only ever receives
   * the state of the conversation it subscribed for.
   */
  const publish = (runtime) => {
    const key = runtime && typeof runtime.sessionId === 'string' ? runtime.sessionId : ''
    for (const stream of streams) {
      if (stream.sessionId !== key) continue
      try {
        stream.push()
      } catch {
        /* a dead subscriber must not break the gate */
      }
    }
  }

  /**
   * One conversation's state as the card receives it.
   *
   * `enabled` is the master switch and is global, but it has to travel on every
   * per-session frame: the icon and the footer switch are rendered from this
   * object, and a card that learned about the master only at mount would keep
   * showing "armed" after another window turned the whole tool off.
   */
  const snapshot = (runtime) => {
    // `liveLog` is deliberately dropped: the entries carry file paths, rule ids
    // and messages, and this frame is broadcast on every icon change. The card
    // gets the counters here and the entries through `live-log`, exactly like it
    // gets `scanRev` here and the findings table through `scan-result`.
    const { liveLog, ...rest } = runtime
    return { ...rest, enabled: settings.enabled, settingsPath }
  }

  /** Push the master switch to every open card, not just the one that flipped it. */
  const publishAll = () => {
    for (const runtime of runtimes.values()) publish(runtime)
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
    publish(runtime)
  }

  /**
   * Fingerprint one workspace's editable configuration.
   *
   * `mtime + size` is enough: a hand edit changes both, and a false positive
   * costs one extra config read in an open card. Hashing the files every two
   * seconds would be the expensive way to learn the same thing.
   */
  const configStamp = (target) => {
    const parts = []
    for (const name of [PROJECT_CONFIG, IGNORE_FILE]) {
      try {
        const info = statSync(join(target, name))
        parts.push(`${name}:${info.mtimeMs}:${info.size}`)
      } catch {
        parts.push(`${name}:-`)
      }
    }
    return parts.join('|')
  }

  /**
   * Remember where this conversation works, and seed its fingerprint.
   *
   * Seeding matters: without it the first watcher tick would see "no previous
   * stamp" as "the file changed" and bump every card's config revision the
   * moment it was opened.
   */
  const configStamps = new Map()
  const historyStamps = new Map()
  const historyStamp = (target) => {
    try {
      const info = statSync(join(target, HISTORY_FILE))
      return `${info.mtimeMs}:${info.size}`
    } catch {
      return '-'
    }
  }
  const noteTarget = (runtime, target) => {
    if (!runtime.target) runtime.target = target
    if (!configStamps.has(target)) configStamps.set(target, configStamp(target))
    if (!historyStamps.has(target)) historyStamps.set(target, historyStamp(target))
  }

  const settingsStampOf = () => {
    try {
      const info = statSync(settingsPath)
      return `${info.mtimeMs}:${info.size}`
    } catch {
      return ''
    }
  }
  let settingsStamp = settingsStampOf()

  /**
   * Notice changes made outside this card.
   *
   * The browser panel and a text editor both write the same two files. A card
   * that only re-read after its own saves would keep showing a disabled rule as
   * enabled — and "looks enabled" is how a user ends up trusting a gate that is
   * not running. A changed master-switch file is picked up here too, so two
   * windows on the same machine agree without a restart.
   */
  const watchTick = () => {
    const nextSettings = settingsStampOf()
    if (nextSettings !== settingsStamp) {
      settingsStamp = nextSettings
      const next = readSettingEnabled(settingsPath)
      if (typeof next === 'boolean' && next !== settings.enabled) {
        settings.enabled = next
        publishAll()
      }
    }
    const targets = new Set()
    for (const runtime of runtimes.values()) {
      if (runtime.target) targets.add(runtime.target)
    }
    for (const target of targets) {
      const next = configStamp(target)
      const previous = configStamps.get(target)
      if (previous === undefined) {
        configStamps.set(target, next)
        continue
      }
      if (previous === next) continue
      configStamps.set(target, next)
      for (const runtime of runtimes.values()) {
        if (runtime.target !== target) continue
        runtime.configRev = (runtime.configRev || 0) + 1
        publish(runtime)
      }
    }
    for (const target of targets) {
      const next = historyStamp(target)
      const previous = historyStamps.get(target)
      if (previous === undefined) {
        historyStamps.set(target, next)
        continue
      }
      if (previous === next) continue
      historyStamps.set(target, next)
      // A repair made in the browser panel lands in the same JSONL the card
      // reads. Without this an open history tab kept showing the trail as of its
      // last local edit — the card knew only about repairs it made itself.
      for (const runtime of runtimes.values()) {
        if (runtime.target !== target) continue
        runtime.historyRev = (runtime.historyRev || 0) + 1
        publish(runtime)
      }
    }
  }

  /**
   * Whether `path` lives inside this conversation's workspace.
   *
   * The isolation rule the whole live view depends on: one window watches one
   * project. A write the agent makes outside `runtime.target` (a global config,
   * a sibling checkout, the harness's own data directory) is still gated — the
   * hook runs either way — but it must not appear in *this* project's live
   * trail, or two open windows would each claim the other's files.
   *
   * The comparison is on resolved absolute paths with a separator check, not a
   * naive `startsWith`: `/work/app-legacy/x.py` starts with `/work/app` and is a
   * different project.
   */
  const insideTarget = (runtime, path) => {
    if (!runtime || typeof runtime.target !== 'string' || !runtime.target) return false
    if (typeof path !== 'string' || !path) return false
    let absolute
    try {
      absolute = resolve(path)
    } catch {
      return false
    }
    const root = resolve(runtime.target)
    if (absolute === root) return true
    return absolute.startsWith(root.endsWith(sep) ? root : root + sep)
  }

  /**
   * The label a live entry shows for one inspected path.
   *
   * A workspace-relative path is what the user recognises ("src/app.py"), and it
   * keeps the state frame small. Anything outside the workspace never reaches
   * here — `insideTarget` filtered it — so the fallback is only for a path that
   * resolves oddly (a symlink, a different drive letter).
   */
  const relativeLabel = (runtime, path) => {
    try {
      const root = resolve(runtime.target)
      const absolute = resolve(path)
      const relative = absolute === root ? '.' : absolute.slice(root.endsWith(sep) ? root.length : root.length + 1)
      return relative || String(path)
    } catch {
      return String(path)
    }
  }

  /**
   * Turn one hook report into the compact entry the live trail keeps.
   *
   * The report is the hook's own machine channel; `findings` is capped so one
   * pathological file cannot put a thousand rows on the state frame. The trail
   * is a *ticker*, not the findings table — the table lives in the audit tab.
   */
  const liveEntry = (runtime, item, verdict, counts, findings) => {
    const list = Array.isArray(findings) ? findings : []
    const worst = list.reduce((rank, finding) => {
      const level = String(finding?.severity || '').toUpperCase()
      const next = level === 'CRITICAL' ? 2 : level === 'WARNING' ? 1 : 0
      return next > rank ? next : rank
    }, 0)
    return {
      at: Date.now(),
      /** What the card shows: a workspace-relative path, or the shell command. */
      file: String(item?.label || item?.path || ''),
      /** `write` for a file mutation, `shell` for a command that may write. */
      kind: item?.shell ? 'shell' : 'write',
      verdict,
      severity: worst === 2 ? 'CRITICAL' : worst === 1 ? 'WARNING' : counts.critical ? 'CRITICAL' : counts.warning ? 'WARNING' : 'INFO',
      critical: counts.critical,
      warning: counts.warning,
      info: counts.info,
      rule: String(list[0]?.rule_id || ''),
      message: String(list[0]?.message || ''),
      findings: list.slice(0, 5).map((finding) => ({
        rule_id: String(finding?.rule_id || ''),
        severity: String(finding?.severity || ''),
        line: Number(finding?.line || 0),
        message: String(finding?.message || ''),
      })),
    }
  }

  /**
   * Append one inspected write to a conversation's live trail.
   *
   * Called from `inspect()` — i.e. on every tool call the gate actually looked
   * at, whether it was allowed or blocked. That is what makes the card live: no
   * button press, no polling, the entry exists the moment the write is decided.
   */
  const recordLive = (runtime, item, verdict, counts, findings) => {
    if (!runtime) return
    const entry = liveEntry(runtime, item, verdict, counts, findings)
    runtime.liveChecked = (runtime.liveChecked || 0) + 1
    if (verdict === 'BLOCK' || verdict === 'REVIEW') runtime.liveHits = (runtime.liveHits || 0) + 1
    if (!runtime.liveSince) runtime.liveSince = entry.at
    const log = Array.isArray(runtime.liveLog) ? runtime.liveLog : []
    log.push(entry)
    if (log.length > LIVE_LOG_LIMIT) log.splice(0, log.length - LIVE_LOG_LIMIT)
    runtime.liveLog = log
    runtime.liveRev = (runtime.liveRev || 0) + 1
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

  /**
   * Fold one full-audit verdict into a conversation's state.
   *
   * Shared by the card's "run scan" button and the automatic session-created
   * audit: two copies of this branch would eventually disagree about whether a
   * clean audit clears the sticky alert, and the icon would depend on which door
   * the scan came through.
   */
  const applyScanResult = (runtime, result) => {
    runtime.files = result.files
    runtime.verdict = result.verdict
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
      // A full audit is the one thing that may lower the sticky alert: the user
      // asked for a whole-project answer, and it came back clean.
      runtime.alert = ''
      setPhase(runtime, 'clean', { ...counts, lastMessage: result.message })
    }
  }

  /**
   * Run the first audit as soon as a conversation is created.
   *
   * This is the "if it is on, it works by itself" half of the master switch.
   * It is intentionally asynchronous: a scan of a large tree can take minutes,
   * and blocking `session/created` would freeze the window that just opened.
   * Sub-agent sessions are skipped — their workspace is the parent's, and
   * auditing it once per delegated child would multiply the same work.
   */
  const autoScanSession = (session) => {
    if (!settings.enabled || !scannerReady) return
    const header = session?.header
    if (!header) return
    if (header.parentSession || Number(header.delegationDepth || 0) > 0) return
    const target = typeof header.cwd === 'string' ? header.cwd : ''
    if (!target || !isAbsolute(target) || !isDirectory(target)) return
    // A session that has not been attached to a workspace yet can carry the home
    // directory (or a drive root) as its cwd. Auditing that is never what the
    // user meant, and on Windows it can walk the whole profile. The harness's
    // own data directory is excluded for the same reason. Manual scans are not
    // restricted: there the user chose the directory explicitly.
    const resolvedTarget = resolve(target)
    const homeDir = resolve(homedir())
    const dshHome = resolve(process.env.DSH_HOME || join(homedir(), '.dsh'))
    if (resolvedTarget === homeDir || dirname(resolvedTarget) === resolvedTarget) return
    if (resolvedTarget === dshHome || resolvedTarget.startsWith(dshHome + sep)) return
    const sessionId = typeof session?.id === 'string' ? session.id : ''
    const runtime = runtimeFor(sessionId)
    if (runtime.autoScanned) return
    runtime.autoScanned = true
    noteTarget(runtime, target)
    runtime.phase = 'scanning'
    publish(runtime)
    runBridge({
      python,
      skillRoot,
      method: 'scan',
      args: { mode: 'full', include_tests: false },
      target,
      env: envFor(runtime),
      timeoutMs,
    })
      .then((result) => {
        if (result && result.ok && result.data && result.data.summary) {
          const summary = result.data.summary || {}
          const sev = summary.severity || {}
          // Keep the full JSON for the scan tab. Only the revision travels on the
          // state frame, so the icon stays cheap while the table gets real rows.
          scanCache.set(sessionId, result.data)
          runtime.scanRev = (runtime.scanRev || 0) + 1
          applyScanResult(runtime, {
            verdict: String(result.data.verdict || ''),
            files: Number(summary.scanned_files || 0),
            critical: Number(sev.CRITICAL || 0),
            warning: Number(sev.WARNING || 0),
            info: Number(sev.INFO || 0),
            message: String(result.data.verdict || ''),
          })
          return
        }
        // The bridge is the richer path. If it is unavailable (an older skill
        // install without `panel_bridge.py`), still produce the verdict and
        // counters the icon needs instead of leaving the session silent.
        runScan({ target, python, skillRoot, timeoutMs, env: envFor(runtime), blockOn: runtime.blockOn })
          .then((fallback) => applyScanResult(runtime, fallback))
          .catch((error) => setPhase(runtime, 'error', { lastMessage: String(error) }))
      })
      .catch((error) => setPhase(runtime, 'error', { lastMessage: String(error) }))
  }

  /**
   * Start the automatic audit for a conversation that never got one.
   *
   * `session/created` covers new conversations, but the card can be opened in a
   * window that already existed when the plugin loaded (a profile reload, an
   * upgrade, a session resumed from disk). In those the user was left with an
   * empty scan tab and the instruction to press a button — which is exactly the
   * "it only works if I click it" complaint.
   *
   * So the first `state` read from the card also arms the audit, using the
   * workspace the card reports. The same guards as `session/created` apply: no
   * home directory, no drive root, no harness data directory, and a session only
   * ever gets one automatic audit.
   */
  const ensureSessionAudit = (runtime, target) => {
    if (!settings.enabled || !scannerReady) return
    if (runtime.autoScanned) return
    if (typeof target !== 'string' || !target || !isAbsolute(target) || !isDirectory(target)) return
    const resolvedTarget = resolve(target)
    const homeDir = resolve(homedir())
    const dshHome = resolve(process.env.DSH_HOME || join(homedir(), '.dsh'))
    if (resolvedTarget === homeDir || dirname(resolvedTarget) === resolvedTarget) return
    if (resolvedTarget === dshHome || resolvedTarget.startsWith(dshHome + sep)) return
    runtime.autoScanned = true
    // Watching starts now, not when the audit finishes: the agent may write
    // while the audit is still running, and those writes belong in the trail.
    noteTarget(runtime, target)
    runtime.phase = 'scanning'
    publish(runtime)
    runBridge({
      python,
      skillRoot,
      method: 'scan',
      args: { mode: 'full', include_tests: false },
      target,
      env: envFor(runtime),
      timeoutMs,
    })
      .then((result) => {
        if (result && result.ok && result.data && result.data.summary) {
          const summary = result.data.summary || {}
          const sev = summary.severity || {}
          scanCache.set(runtime.sessionId, result.data)
          runtime.scanRev = (runtime.scanRev || 0) + 1
          applyScanResult(runtime, {
            verdict: String(result.data.verdict || ''),
            files: Number(summary.scanned_files || 0),
            critical: Number(sev.CRITICAL || 0),
            warning: Number(sev.WARNING || 0),
            info: Number(sev.INFO || 0),
            message: String(result.data.verdict || ''),
          })
          return
        }
        runScan({ target, python, skillRoot, timeoutMs, env: envFor(runtime), blockOn: runtime.blockOn })
          .then((fallback) => applyScanResult(runtime, fallback))
          .catch((error) => setPhase(runtime, 'error', { lastMessage: String(error) }))
      })
      .catch((error) => setPhase(runtime, 'error', { lastMessage: String(error) }))
  }

  const inspect = async (runtime, hookPath, payload, cwd, kind, files) => {
    if (!hookPath) return { blocked: false, output: '', report: null }
    runtime.phase = 'scanning'
    publish(runtime)
    const result = await runHook({
      python,
      hookPath,
      payload,
      cwd,
      timeoutMs,
      env: envFor(runtime),
      reportPath: makeReportPath(),
    })
    const counts = countsOf(result)
    let verdict = 'SAFE'
    // The transcript line is empty whenever the hook allowed the call, so the
    // verdict comes from the counts. Reading it off stderr made every clean pass
    // look like it had no opinion.
    if (result.blocked) {
      verdict = 'BLOCK'
      runtime.verdict = 'BLOCK'
      raiseAlert(runtime, 'block')
      setPhase(runtime, 'block', { ...counts, lastMessage: result.output.split('\n')[0] || '' })
    } else if (counts.critical || counts.warning) {
      // The scanner ran and found something below the block threshold; the
      // badge stays amber so a WARNING-only pass is not reported as clean.
      verdict = counts.critical ? 'BLOCK' : 'REVIEW'
      runtime.verdict = verdict
      raiseAlert(runtime, counts.critical ? 'block' : 'warn')
      setPhase(runtime, 'warn', { ...counts, lastMessage: result.report?.findings?.[0]?.message || '' })
    } else {
      runtime.verdict = 'SAFE'
      // Keep the last incident's counters while an alert is pending: showing
      // "C 0 / W 0" next to a red icon reads like a contradiction. They are
      // cleared together with the alert, by `reset` or a clean full audit.
      const keep = runtime.alert ? { critical: runtime.critical, warning: runtime.warning, info: runtime.info } : counts
      setPhase(runtime, 'clean', keep)
    }
    // The live trail. This is the whole point of "monitoring": the entry exists
    // as soon as the write was decided, without anybody pressing a button.
    //
    // Only paths inside this conversation's own workspace are recorded. The hook
    // still gated the write either way, but a second window on a different
    // project must never see this one's files in its own trail — that is the
    // isolation the whole per-session state exists for.
    const findings = Array.isArray(result.report?.findings) ? result.report.findings : []
    const watched = Array.isArray(files) ? files : []
    for (const item of watched) {
      if (!item) continue
      // A shell command has no file path to scope by, and it belongs to exactly
      // one conversation already. It is recorded only when it actually tripped a
      // rule: a trail full of `echo hello` would bury the writes the user cares
      // about, while a caught `curl … | bash` is precisely what they need to see.
      if (item.shell) {
        if (verdict === 'SAFE') continue
        recordLive(runtime, item, verdict, counts, findings)
        continue
      }
      if (!insideTarget(runtime, item.path)) continue
      recordLive(runtime, { ...item, label: relativeLabel(runtime, item.path) }, verdict, counts, findings)
    }
    if (watched.length) publish(runtime)
    return result
  }

  /**
   * A fresh file for one hook run's machine report.
   *
   * One per call, not one per plugin: two windows inspecting files at the same
   * time would otherwise interleave their JSON lines in a shared file and each
   * would read the other's verdict.
   */
  const makeReportPath = () => {
    try {
      return join(mkdtempSync(join(tmpdir(), 'dsh-cq-')), 'report.jsonl')
    } catch {
      return ''
    }
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

  /**
   * The workspace this tool call belongs to, read from the session itself.
   *
   * `session.header.cwd` is the same field `session/created` reads, so the answer
   * does not depend on the card being open. That matters for the first write of a
   * conversation: monitoring has to be live from the start, and waiting for the
   * user to click the icon would leave that first file unwatched.
   */
  const targetOf = (exec) => {
    try {
      const cwd = exec?.agent?.session?.header?.cwd
      return typeof cwd === 'string' ? cwd : ''
    } catch {
      return ''
    }
  }

  ctx.on('tools/pre-execute', async (exec, next) => {
    const toolName = String(exec?.name ?? '')
    const args = exec?.arguments
    const cwd = process.cwd()
    const runtime = runtimeFor(sessionOf(exec))

    if (!settings.enabled) return next()
    if (!runtime.armed) return next()
    // Learn the workspace from the session, not from the card: a conversation
    // whose card was never opened must still be monitored live.
    if (!runtime.target) {
      const fromSession = targetOf(exec)
      if (fromSession && isAbsolute(fromSession) && isDirectory(fromSession)) noteTarget(runtime, fromSession)
    }

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
        const result = await inspect(runtime, writeHook, payload, cwd, 'write', edits.map((e) => ({ path: e.path })))
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
        const result = await inspect(runtime, shellHook, payload, cwd, 'shell', [{ shell: true, label: command }])
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
            // Opening the card is enough to start the automatic audit; the user
            // must never have to press "run scan" to get the first answer.
            const requested = typeof args.target === 'string' ? args.target.trim() : ''
            if (requested && isAbsolute(requested) && isDirectory(requested)) noteTarget(runtime, requested)
            ensureSessionAudit(runtime, requested || runtime.target)
            writeJson(response, 200, { ok: true, state: snapshot(runtime) })
            return
          }
          if (method === 'scan-result') {
            // The card asks for this once per `scanRev` (and on open), not on
            // every frame: findings can be large, and the live state must stay
            // small enough to broadcast on each icon colour change.
            writeJson(response, 200, { ok: true, data: scanCache.get(sessionId) || null, state: snapshot(runtime) })
            return
          }
          if (method === 'live-log') {
            // The live trail, read once per `liveRev` (and on open). Same reason
            // as `scan-result`: entries are bigger than a counter, and the state
            // frame is what every icon colour change rides on.
            const log = Array.isArray(runtime.liveLog) ? runtime.liveLog : []
            const limit = Number.isFinite(Number(args.limit)) && Number(args.limit) > 0
              ? Math.min(Number(args.limit), LIVE_LOG_LIMIT)
              : LIVE_SHOW_LIMIT
            writeJson(response, 200, {
              ok: true,
              data: {
                entries: log.slice(Math.max(0, log.length - limit)),
                total: log.length,
                checked: runtime.liveChecked || 0,
                hits: runtime.liveHits || 0,
                since: runtime.liveSince || 0,
                watching: Boolean(runtime.target),
                target: runtime.target || '',
              },
              state: snapshot(runtime),
            })
            return
          }
          if (method === 'master') {
            // The one preference that is not per conversation. It gates the
            // automatic half only: a user who turns it off still gets a working
            // icon, a full settings card and manual scans, so turning it back on
            // never requires editing the profile patch or restarting the host.
            const next = args.enabled !== false
            let persisted = true
            if (next !== settings.enabled) {
              settings.enabled = next
              persisted = writeSettingEnabled(settingsPath, next, ctx.logger)
              settingsStamp = settingsStampOf()
              publishAll()
            }
            writeJson(response, 200, { ok: true, persisted, state: snapshot(runtime) })
            return
          }
          if (method === 'arm') {
            runtime.armed = args.armed !== false
            if (!runtime.armed) runtime.phase = 'disarmed'
            else if (runtime.phase === 'disarmed') runtime.phase = 'idle'
            publish(runtime)
            writeJson(response, 200, { ok: true, state: snapshot(runtime) })
            return
          }
          if (method === 'configure') {
            const next = String(args.blockOn || '').toLowerCase()
            if (next === 'critical' || next === 'warning') {
              // Only this conversation's threshold. `envFor(runtime)` builds the
              // scanner environment per call, so there is no shared env object to
              // mutate — mutating one would retune every other window.
              runtime.blockOn = next
              publish(runtime)
            }
            writeJson(response, 200, { ok: true, state: snapshot(runtime) })
            return
          }
          if (method === 'audit') {
            if (!scannerReady) {
              writeJson(response, 200, { ok: false, code: 'NO_SCANNER', state: snapshot(runtime) })
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
            noteTarget(runtime, target)
            const result = await runScan({ target, python, skillRoot, timeoutMs, env: envFor(runtime), blockOn: runtime.blockOn })
            applyScanResult(runtime, result)
            writeJson(response, 200, { ok: true, state: snapshot(runtime) })
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
            publish(runtime)
            writeJson(response, 200, { ok: true, state: snapshot(runtime) })
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
            noteTarget(runtime, target)
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
              // Keep the table addressable by revision, exactly like the automatic
              // audit. A card that was reloaded (or a second window on the same
              // session) can then show the last result without running the scan
              // again.
              scanCache.set(sessionId, result.data)
              runtime.scanRev = (runtime.scanRev || 0) + 1
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
              result.state = snapshot(runtime)
            }
            // Two counters, one frame. A repair writes a line *and* appends to the
            // trail, and a config write invalidates the card's cached forms; both
            // are "something changed elsewhere". Publishing after each bump would
            // send an intermediate frame whose second counter is still stale, so
            // the card would re-read the trail and then immediately re-read again.
            let bumped = false
            if (result.ok && (op === 'line-write' || op === 'save' || op === 'ignore')) {
              runtime.historyRev = (runtime.historyRev || 0) + 1
              bumped = true
              if (op === 'line-write') historyStamps.set(target, historyStamp(target))
            }
            if (result.ok && (op === 'save' || op === 'ignore' || op === 'baseline')) {
              runtime.configRev = (runtime.configRev || 0) + 1
              bumped = true
              // The write above is this card's own: record the new fingerprint so
              // the watcher does not report it as "changed elsewhere" two seconds
              // later and make every save cause a second redundant re-read.
              configStamps.set(target, configStamp(target))
            }
            if (bumped) {
              publish(runtime)
              result.state = snapshot(runtime)
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

  /**
   * The live feed: one SSE response per open card.
   *
   * `EventSource` cannot set headers, so the session travels in the query string
   * instead of the request body. That is also why this route is `GET`-only: a
   * stream has no response to "return" and the browser will not issue a POST for
   * it anyway.
   */
  const registerEvents = () => {
    const webServer = typeof ctx.get === 'function' ? ctx.get('webServer') : undefined
    if (!webServer || typeof webServer.register !== 'function') return () => {}
    return webServer.register({
      kind: 'exact',
      path: EVENT_PATH,
      handler: (request, response) => {
        if (!isSameOrigin(request)) {
          writeJson(response, 403, { ok: false, code: 'FORBIDDEN_ORIGIN' })
          return
        }
        let sessionId = ''
        try {
          sessionId = new URL(request.url, 'http://localhost').searchParams.get('session') || ''
        } catch {
          sessionId = ''
        }
        const runtime = runtimeFor(sessionId)

        response.writeHead(200, {
          'content-type': 'text/event-stream; charset=utf-8',
          'cache-control': 'no-store, no-transform',
          connection: 'keep-alive',
          // Nginx-style proxies buffer by default and would turn a live feed into
          // a batch delivery; this header is the standard opt-out.
          'x-accel-buffering': 'no',
        })
        // `EventSource` reconnects on its own, but it starts with `retry` unset;
        // stating it makes the recovery interval explicit rather than browser
        // default (3s in Chrome, longer elsewhere).
        response.write('retry: 2000\n\n')

        const stream = {
          sessionId,
          push: () => {
            // A single `data:` line: the state object is JSON with no newlines, so
            // the SSE framing stays trivial and cannot be broken by a message
            // containing "\n" (which is exactly what a scanner report has).
            response.write(`data: ${JSON.stringify({ state: snapshot(runtime) })}\n\n`)
          },
        }
        streams.add(stream)
        stream.push()

        const heartbeat = setInterval(() => {
          try {
            response.write(': keep-alive\n\n')
          } catch {
            /* the close handler below will clean up */
          }
        }, EVENT_HEARTBEAT_MS)
        if (typeof heartbeat.unref === 'function') heartbeat.unref()

        const close = () => {
          clearInterval(heartbeat)
          streams.delete(stream)
        }
        request.on('close', close)
        response.on('close', close)
        response.on('error', close)
      },
    })
  }

  // The automatic half of the master switch: a fresh conversation gets one
  // audit of its workspace, asynchronously, and its icon reflects the result.
  // A throwing listener would roll the session attach back, so every failure is
  // contained here — the gate is plumbing, not a reason a window cannot open.
  ctx.on('session/created', (session) => {
    try {
      autoScanSession(session)
    } catch (error) {
      ctx.logger?.warn?.('dsh-code-quarantine: session/created audit failed: %s', String(error))
    }
  })

  // A conversation that went away must not leave its state (and target) behind
  // for the watcher to keep stat-ing forever.
  ctx.on('session/disposed', (session) => {
    const id = typeof session?.id === 'string' ? session.id : ''
    runtimes.delete(id)
    scanCache.delete(id)
  })

  // External edits (the browser panel, a text editor) and a master switch
  // flipped in another window both arrive through this tick. It is a timer, not
  // a watch: two files in a project directory, and `fs.watch` is unreliable
  // across editors and network drives for the same result.
  ctx.effect(
    () => {
      const timer = setInterval(watchTick, CONFIG_WATCH_MS)
      timer.unref?.()
      return () => clearInterval(timer)
    },
    'dsh-code-quarantine: config watch',
  )

  if (typeof ctx.inject === 'function') {
    ctx.inject(['webServer'], (hostCtx) =>
      hostCtx.effect(() => {
        // One effect owns both routes so a web-server restart re-registers them
        // together; splitting them would let the RPC come back while the feed
        // silently stayed dead.
        const offRpc = registerRoute()
        const offEvents = registerEvents()
        return () => {
          offRpc()
          offEvents()
        }
      }, 'dsh-code-quarantine: routes'),
    )
  } else {
    ctx.effect(
      () => {
        const offRpc = registerRoute()
        const offEvents = registerEvents()
        return () => {
          offRpc()
          offEvents()
        }
      },
      'dsh-code-quarantine: routes',
    )
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
