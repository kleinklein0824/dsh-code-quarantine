/**
 * Client-half behaviour tests: mount `QuarantineButton` in a tiny hand-rolled
 * renderer and drive real DOM events at it.
 *
 * Why not jsdom + react-dom: neither is a dependency of this repo, and neither is
 * resolvable from a bare checkout. A ~200 line shim is enough to run the hooks in
 * order, rebuild the tree on setState, and answer the only DOM questions this
 * component asks (`ref`, `contains`, `addEventListener`). The bug these tests
 * guard against — the panel closing on its own first click — lives entirely in
 * that interaction, and it cannot be caught by reading the source or by calling
 * the RPC by hand.
 */

import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const SOURCE = readFileSync(join(HERE, 'client.js'), 'utf8')

let failures = 0
function record(name, ok, detail) {
  if (!ok) failures += 1
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `  <- ${detail}`}`)
}

/* ------------------------------------------------------------------ fake DOM */

class FakeNode {
  constructor(tag) {
    this.tag = tag
    this.parent = null
    this.children = []
    this.listeners = new Map()
    this.attributes = new Map()
    this.textContent = ''
    this.style = {}
  }

  setAttribute(name, value) {
    this.attributes.set(name, value)
  }

  getAttribute(name) {
    return this.attributes.get(name) ?? null
  }

  remove() {
    if (!this.parent) return
    const index = this.parent.children.indexOf(this)
    if (index >= 0) this.parent.children.splice(index, 1)
    this.parent = null
  }

  append(child) {
    child.parent = this
    this.children.push(child)
    return child
  }

  appendChild(child) {
    return this.append(child)
  }

  contains(node) {
    let cursor = node
    while (cursor) {
      if (cursor === this) return true
      cursor = cursor.parent
    }
    return false
  }

  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set())
    this.listeners.get(type).add(fn)
  }

  removeEventListener(type, fn) {
    this.listeners.get(type)?.delete(fn)
  }

  getBoundingClientRect() {
    return { right: 1000, top: 900, left: 972, bottom: 928, width: 28, height: 28 }
  }

  dispatch(type, target) {
    const set = this.listeners.get(type)
    if (!set) return
    for (const fn of [...set]) fn({ type, target: target || this, key: '' })
  }

  listenerCount(type) {
    return this.listeners.get(type)?.size || 0
  }
}

class FakeDocument extends FakeNode {
  constructor() {
    super('#document')
    this.head = this.append(new FakeNode('head'))
  }

  createElement(tag) {
    return new FakeNode(tag)
  }
}

/**
 * Stand-in for the browser's `EventSource`.
 *
 * The card subscribes to the Host's live feed instead of polling, so the tests
 * have to be able to push a frame the way the server would. Keeping the class
 * here (rather than a stub that swallows everything) also lets a test assert
 * that a frame for one conversation repaints one card and not another.
 */
function installGlobals() {
  const document = new FakeDocument()
  const timers = []
  const sources = []
  globalThis.document = document
  globalThis.window = {
    innerWidth: 1400,
    innerHeight: 900,
    setInterval: (fn) => {
      const handle = { fn, repeat: true }
      timers.push(handle)
      return handle
    },
    clearInterval: (handle) => {
      const index = timers.indexOf(handle)
      if (index >= 0) timers.splice(index, 1)
    },
    setTimeout: (fn) => {
      const handle = { fn, repeat: false }
      timers.push(handle)
      return handle
    },
    EventSource: class FakeEventSource {
      constructor(url) {
        this.url = url
        this.onmessage = null
        this.onerror = null
        this.closed = false
        sources.push(this)
      }

      /** Deliver one `data:` frame, exactly as the Host's stream would. */
      emit(payload) {
        if (this.closed || typeof this.onmessage !== 'function') return
        this.onmessage({ data: JSON.stringify(payload) })
      }

      fail() {
        if (!this.closed && typeof this.onerror === 'function') this.onerror({})
      }

      close() {
        this.closed = true
      }
    },
  }
  globalThis.setTimeout = globalThis.window.setTimeout
  globalThis.clearTimeout = () => {}
  // Node 26 defines `navigator` as a getter-only global; defineProperty is the
  // only way to swap it without touching the real one.
  Object.defineProperty(globalThis, 'navigator', {
    value: { clipboard: { writeText: async () => {} } },
    configurable: true,
    writable: true,
  })
  return { document, timers, sources }
}

/* --------------------------------------------------------------- fake react */

const FRAGMENT = Symbol('fragment')

function createReact() {
  const slots = []

  function current() {
    const slot = slots[slots.length - 1]
    if (!slot) throw new Error('hook used outside a render')
    const index = slot.cursor++
    return { slot, index }
  }

  const React = {
    Fragment: FRAGMENT,
    createElement(type, props, ...children) {
      const list = children.flat(Infinity).filter((c) => c != null && c !== false)
      // Real React exposes children on `props.children` as well as passing them
      // positionally. Small wrappers like `Row = (props) => h('div', null, props.children)`
      // rely on that, so omitting it made every such wrapper render an empty div.
      const merged = { ...(props || {}) }
      if (list.length) merged.children = list.length === 1 ? list[0] : list
      return { type, props: merged, children: list }
    },
    useState(initial) {
      const { slot, index } = current()
      if (!(index in slot.state)) slot.state[index] = typeof initial === 'function' ? initial() : initial
      const set = (next) => {
        const value = typeof next === 'function' ? next(slot.state[index]) : next
        if (Object.is(value, slot.state[index])) return
        slot.state[index] = value
        slot.rerender()
      }
      return [slot.state[index], set]
    },
    useRef(initial) {
      const { slot, index } = current()
      if (!(index in slot.refs)) slot.refs[index] = { current: initial }
      return slot.refs[index]
    },
    useCallback(fn, deps) {
      const { slot, index } = current()
      const previous = slot.memos[index]
      const same = previous && depsEqual(previous.deps, deps)
      if (!same) slot.memos[index] = { deps, fn }
      return slot.memos[index].fn
    },
    useEffect(fn, deps) {
      const { slot, index } = current()
      slot.effects.push({ index, deps, fn })
    },
  }

  function depsEqual(a, b) {
    if (!a || !b || a.length !== b.length) return false
    return a.every((value, i) => Object.is(value, b[i]))
  }

  /**
   * Render a component function and return the element tree plus the slot that
   * owns its hook state. Re-rendering reuses the same slot, which is what lets
   * setState preserve state across the rebuild.
   */
  function renderComponent(type, props) {
    const slot = { state: {}, refs: {}, memos: {}, effects: [], cursor: 0, lastTree: null, onRender: null }
    const mount = () => {
      slot.cursor = 0
      slot.effects = []
      slots.push(slot)
      let element
      try {
        element = type(props)
      } finally {
        slots.pop()
      }
      const tree = build(element)
      slot.lastTree = tree
      runEffects(slot)
      return tree
    }
    slot.rerender = () => {
      const tree = mount()
      slot.onRender?.(tree)
    }
    return { slot, tree: mount() }
  }

  function runEffects(slot) {
    for (const effect of slot.effects) {
      const previous = slot.memos[`effect:${effect.index}`]
      const same = previous && depsEqual(previous.deps, effect.deps)
      if (same) continue
      if (previous && typeof previous.cleanup === 'function') previous.cleanup()
      const cleanup = effect.fn()
      slot.memos[`effect:${effect.index}`] = { deps: effect.deps, cleanup }
    }
  }

  /**
   * Turn the element tree into FakeNodes. `ref` props are resolved against the
   * instance, which is how the component's outside-click test finds its surfaces.
   */
  function build(element) {
    if (element == null || element === false) return null
    if (typeof element === 'string' || typeof element === 'number') {
      // Keep the text: assertions about what the card *says* (a rule id, a diff
      // line, a backup name) are the only way to test a read-only view.
      const text = new FakeNode('#text')
      text.textContent = String(element)
      return text
    }
    if (Array.isArray(element)) return element.map(build).filter(Boolean)
    if (element.type === FRAGMENT) {
      return element.children.map(build).filter(Boolean)
    }
    // Nested function components (the tab bodies) render as their own subtree.
    // Without this, `build` silently produced an empty node for every tab body and
    // the assertions below would pass by finding nothing to disagree with.
    if (typeof element.type === 'function') {
      const childSlot = { state: {}, refs: {}, memos: {}, effects: [], cursor: 0, lastTree: null, onRender: null }
      slots.push(childSlot)
      let inner
      try {
        inner = element.type(element.props)
      } finally {
        slots.pop()
      }
      runEffects(childSlot)
      return build(inner)
    }
    const node = new FakeNode(element.type)
    if (element.props.ref) element.props.ref.current = node
    if (element.props.className) node.attributes.set('class', element.props.className)
    if (element.props['data-phase']) node.attributes.set('data-phase', element.props['data-phase'])
    // Keep the attributes the card uses to explain itself: `data-on` says whether
    // a switch is on, `aria-label` distinguishes the master switch from the
    // per-session one, and `disabled` is what a turned-off master switch applies
    // to the switch below it.
    for (const [key, value] of Object.entries(element.props)) {
      if (key === 'ref' || typeof value === 'function' || value === undefined || value === null) continue
      if (key === 'disabled') {
        // React omits `disabled` entirely when it is false; mirror that so a test
        // can tell "no attribute" from `disabled="false"`.
        if (value === true) node.attributes.set(key, 'true')
        continue
      }
      if (key.startsWith('data-') || key.startsWith('aria-') || key === 'title') {
        node.attributes.set(key, value)
      }
    }
    // Wire event props so `dispatch('click')` reaches the component's handlers.
    // Without this the whole test is theatre: every dispatch is a no-op and every
    // assertion about open/closed state passes for the wrong reason.
    for (const [key, value] of Object.entries(element.props)) {
      if (key === 'ref' || typeof value !== 'function') continue
      if (key.startsWith('on') && key.length > 2) node.addEventListener(key.slice(2).toLowerCase(), value)
    }
    for (const child of element.children) {
      const built = build(child)
      for (const item of Array.isArray(built) ? built : [built]) {
        if (item) node.append(item)
      }
    }
    return node
  }

  return { React, renderComponent }
}

/* --------------------------------------------------------------- fake host */

function makeBridge() {
  const calls = []
  const rpc = (method, args, target, sessionId) => {
    calls.push({ method, args, target, sessionId })
    if (method === 'state') {
      return Promise.resolve({
        ok: true,
        state: { enabled: true, armed: true, phase: 'clean', alert: '', blockOn: 'critical', critical: 0, warning: 0, info: 0, files: 0 },
      })
    }
    if (method === 'master') {
      return Promise.resolve({
        ok: true,
        state: {
          enabled: args?.enabled !== false,
          armed: true,
          phase: args?.enabled !== false ? 'idle' : 'disarmed',
          alert: '',
          blockOn: 'critical',
          critical: 0,
          warning: 0,
          info: 0,
          files: 0,
        },
      })
    }
    if (method === 'live-log') {
      // What the gate saw while the conversation ran. It is fetched on open and
      // on every `liveRev`, so the card never has to ask "did anything happen?"
      // on a timer.
      return Promise.resolve({
        ok: true,
        data: {
          entries: [
            { at: Date.UTC(2026, 9, 24, 2, 0, 0), file: 'src/a.py', kind: 'write', verdict: 'SAFE', severity: 'INFO', critical: 0, warning: 0, info: 0, rule: '', message: '', findings: [] },
            { at: Date.UTC(2026, 9, 24, 2, 1, 0), file: 'src/b.py', kind: 'write', verdict: 'BLOCK', severity: 'CRITICAL', critical: 1, warning: 0, info: 0, rule: 'SC101', message: '远程下载后管道执行', findings: [] },
          ],
          total: 2,
          checked: 2,
          hits: 1,
          since: Date.UTC(2026, 9, 24, 2, 0, 0),
          watching: true,
          target: 'C:/work/demo',
        },
        state: { enabled: true, armed: true, phase: 'block', alert: 'block', blockOn: 'critical', critical: 1, warning: 0, info: 0, files: 0, liveRev: 1 },
      })
    }
    if (method === 'panel') {
      const op = args?.op
      if (op === 'state') {
        return Promise.resolve({
          ok: true,
          data: {
            version: '1.2.0',
            target,
            rules: [
              { id: 'AD001', title: '推广话术', category: 'ad_injection', severity: 'WARNING', default_severity: 'WARNING', enabled: true, default_enabled: true, message: 'm', suggestion: 's' },
            ],
            llm: { enabled: false, ready: false, provider: 'openai', base_url: '', model: '', api_key_env: 'DSH_QUARANTINE_LLM_API_KEY', timeout: 30, max_chars: 6000, max_calls: 20, has_key: false },
            allow: { domains: [], blocked_domains: [], registries: [], cdn_domains: [] },
            ignore: [],
            files: { config: '.dsh-quarantine.yml', config_exists: false, ignore: '.dsh-quarantine-ignore', ignore_exists: true },
            warnings: [],
          },
        })
      }
      if (op === 'scan') {
        // A project with nothing wrong: the verdict is SAFE, the finding list is
        // empty, and the panel still has to say something true about that.
        return Promise.resolve({
          ok: true,
          data: {
            verdict: 'SAFE',
            findings: [],
            warnings: [],
            summary: { scanned_files: 42, severity: { CRITICAL: 0, WARNING: 0, INFO: 0 } },
          },
          state: { armed: true, phase: 'clean', alert: '' },
        })
      }
      if (op === 'history') {
        return Promise.resolve({
          ok: true,
          data: {
            path: '.dsh-quarantine-history.jsonl',
            total: 2,
            entries: [
              {
                kind: 'fix',
                file: 'src/a.py',
                line: 12,
                before: '    os.system(cmd)',
                after: '    subprocess.run(["ls"])',
                backup: '.dsh-quarantine-backup/src__a.py.20261022-101500.bak',
                rule_id: 'SC101',
                source: 'card',
                remaining: 0,
                clock: '10:15:00',
                iso: '2026-10-22T10:15:00',
                status: 'current',
              },
              {
                kind: 'fix',
                file: 'src/b.py',
                line: 3,
                before: 'BASE = "https://api.cheap-relay.com/v1"',
                after: 'BASE = "https://api.openai.com/v1"',
                backup: '.dsh-quarantine-backup/src__b.py.20261022-101400.bak',
                rule_id: 'AD003',
                source: 'panel',
                remaining: 0,
                clock: '10:14:00',
                iso: '2026-10-22T10:14:00',
                // 有人事后把文件改回去了：这条记录不再代表现状。
                status: 'reverted',
              },
            ],
          },
        })
      }
      return Promise.resolve({ ok: true, data: {} })
    }
    return Promise.resolve({ ok: true, state: { armed: true, phase: 'clean', alert: '' } })
  }
  return { calls, rpc }
}

/** Load client.js with fake globals and return its factory namespace. */
function loadClient({ document }) {
  const bridge = makeBridge()
  let captured = null
  globalThis.window.__ModuleLoader__ = { load: (definition) => (captured = definition) }
  // Route the component's fetch through the recording bridge so the test can see
  // which method, args and — critically — which `target` each call carried.
  globalThis.fetch = (url, options) => {
    const body = JSON.parse(options.body)
    return bridge.rpc(body.method, body.args, body.target, body.sessionId).then((payload) => ({
      ok: true,
      json: () => Promise.resolve(payload),
    }))
  }
  const react = createReact()
  const React = react.React
  // The factory calls `require('react')`; hand it the shim.
  const factory = (name) => {
    if (name === 'react') return React
    throw new Error(`unexpected require: ${name}`)
  }
  const script = SOURCE.replace(/^window\.__ModuleLoader__\.load\(/m, 'globalThis.__capture(')
  const run = new Function('globalThis', 'require', script)
  run({ __capture: (definition) => (captured = definition) }, factory)
  if (!captured) throw new Error('client.js did not register itself')
  const namespace = captured.factory(factory)
  // The renderer must come from the same instance: hooks live in a module-level
  // stack inside `createReact`, so a second instance cannot see the component's
  // hook slot.
  return { namespace, bridge, React, document, renderComponent: react.renderComponent }
}

const tick = () => new Promise((resolve) => setImmediate(resolve))

/* -------------------------------------------------------------------- tests */

const globals = installGlobals()
const { namespace, bridge, renderComponent } = loadClient(globals)
record('client exports a slots-only plugin', Array.isArray(namespace.inject) && namespace.inject.includes('slots'), JSON.stringify(namespace.inject))

// Mount through the real slot registration path so the test uses the same props
// the renderer would pass (including `useSessions` and `sessionId`).
const registrations = []
const fakeContext = {
  effect(fn) {
    const cleanup = fn()
    return typeof cleanup === 'function' ? cleanup : () => {}
  },
  get(name) {
    if (name === 'locale') return { register() {}, bind: () => (key) => key, getLocale: () => ({ active: 'zh' }) }
    return undefined
  },
  slots: {
    inject(key, fn) {
      fn()
    },
    register(registration, component) {
      registrations.push({ registration, component })
      return () => {}
    },
  },
}
namespace.apply(fakeContext)
record('registers exactly one slot entry', registrations.length === 1, `count=${registrations.length}`)
const entry = registrations[0]
record('registers on conversation.input.right', entry?.registration?.name === 'conversation.input.right', entry?.registration?.name)
record('uses the documented order', entry?.registration?.order === 30, String(entry?.registration?.order))

// A neutral absolute path, not the machine this was written on: the assertion is
// "the card forwards the Session's workspace", not "this checkout exists here".
const WORKSPACE = resolve('/workspace/sample-project')
const props = {
  sessionId: 'session-1',
  useSessions: () => ({ byId: { 'session-1': { cwd: WORKSPACE } } }),
  locale: { getLocale: () => ({ active: 'zh' }) },
}

const { slot, tree } = renderComponent(entry.component, props)
const buttonNode = findButton(tree)
record('renders the icon button', Boolean(buttonNode) && buttonNode.tag === 'button', buttonNode?.tag)

const isOpen = () => {
  const nodes = []
  slot.onRender = (next) => nodes.push(next)
  return nodes
}

/* ---- 1. open the panel ---- */
buttonNode.dispatch('click')
await tick()
record('clicking the icon opens the panel', Boolean(findCard(slot.lastTree)), 'no card in the rendered tree')

/* The card is the sibling of the button: [button, card]. */
function findCard(tree) {
  const list = Array.isArray(tree) ? tree : [tree]
  for (const node of list) {
    if (node && node.attributes?.get('class') === 'dsh-cq-card') return node
  }
  return null
}

function findButton(tree) {
  const list = Array.isArray(tree) ? tree : [tree]
  for (const node of list) {
    if (node && node.attributes?.get('class') === 'dsh-cq-btn') return node
  }
  return null
}

const card = findCard(slot.lastTree)
record('panel card is rendered next to the button', Boolean(card), 'no card node found')

/* ---- 2. mousedown inside the card must NOT close it ---- */
const tabNode = new FakeNode('button')
card.append(tabNode)
globals.document.dispatch('mousedown', tabNode)
await tick()
record(
  'mousedown inside the card keeps the panel open',
  Boolean(findCard(slot.lastTree)),
  'panel closed itself on an inside click (regression: outside-click test only knew about the button)',
)

/* ---- 3. mousedown outside closes it ---- */
const outside = new FakeNode('div')
globals.document.append(outside)
globals.document.dispatch('mousedown', outside)
await tick()
record('mousedown outside the card closes the panel', !findCard(slot.lastTree), 'panel stayed open on an outside click')

/* ---- 4. reopen works, repeatedly ---- */
for (let round = 1; round <= 3; round += 1) {
  const btn = findButton(slot.lastTree)
  if (!btn) {
    record(`round ${round}: icon button still present`, false, 'button missing after close')
    break
  }
  btn.dispatch('click')
  await tick()
  const card2 = findCard(slot.lastTree)
  const inner = new FakeNode('span')
  if (card2) card2.append(inner)
  globals.document.dispatch('mousedown', inner)
  await tick()
  const stillOpen = Boolean(findCard(slot.lastTree))
  record(`round ${round}: reopen and click inside keeps it open`, Boolean(card2) && stillOpen, `card=${Boolean(card2)} open=${stillOpen}`)
  const out = new FakeNode('div')
  globals.document.append(out)
  globals.document.dispatch('mousedown', out)
  await tick()
  record(`round ${round}: outside click closes it again`, !findCard(slot.lastTree), 'panel stayed open')
}

/* ---- 5. the card ref is actually wired ---- */
record('card ref points at the rendered card', Object.values(slot.refs || {}).some((r) => r.current && r.current.attributes?.get('class') === 'dsh-cq-card'), 'no ref resolved to the card node')

/* ---- 6. target travels with every panel call ---- */
const panelCalls = bridge.calls.filter((c) => c.method === 'panel')
record('panel calls carry the session workspace', panelCalls.length > 0 && panelCalls.every((c) => c.target === WORKSPACE), JSON.stringify(panelCalls.map((c) => c.target)))

/* ---- 7. every call is scoped to this conversation ---- */
//
// The Host keeps one gate state per conversation. Without the id it cannot tell
// which window is asking, so a switch flipped in one window would show up in
// all of them — the opposite of a per-workspace safety gate.
const allCalls = bridge.calls
record(
  'every host call carries this conversation id',
  allCalls.length > 0 && allCalls.every((c) => c.sessionId === 'session-1'),
  JSON.stringify(allCalls.map((c) => `${c.method}:${c.sessionId}`)),
)
record(
  'the gate state is read for this conversation, not globally',
  bridge.calls.some((c) => c.method === 'state' && c.sessionId === 'session-1'),
  JSON.stringify(bridge.calls.filter((c) => c.method === 'state').map((c) => c.sessionId)),
)

/* ---- 7. the fix history is reachable and renders the audit trail ---- */
// The question this tab answers is "what did this tool change, and can I prove
// it?" — so the assertions are about the *evidence* being on screen, not about a
// component existing: the rule id, the before/after diff, and the backup path.
// The rounds above each end with an outside click, so the card is closed here.
// Reopen it before looking for the tab — otherwise this test would be asserting
// about a tree that has no card in it at all.
findButton(slot.lastTree)?.dispatch('click')
await tick()

/** Depth-first text of every node under `node`, which may be an array (the tree is a Fragment). */
function allText(node, out = []) {
  if (!node) return out
  if (Array.isArray(node)) {
    for (const item of node) allText(item, out)
    return out
  }
  if (node.textContent) out.push(node.textContent)
  for (const child of node.children || []) allText(child, out)
  return out
}

/** Every node whose class starts with `prefix`, arrays included. */
function findAll(node, prefix, out = []) {
  if (!node) return out
  if (Array.isArray(node)) {
    for (const item of node) findAll(item, prefix, out)
    return out
  }
  const cls = node.attributes?.get('class')
  if (cls && cls.startsWith(prefix)) out.push(node)
  for (const child of node.children || []) findAll(child, prefix, out)
  return out
}

const historyTab = findAll(slot.lastTree, 'dsh-cq-tab').find((node) => allText(node).join('') === '修复历史') || null
record('history tab is offered in the card', Boolean(historyTab), `tabs=${findAll(slot.lastTree, 'dsh-cq-tab').map((n) => allText(n).join('')).join('/')}`)

if (historyTab) {
  historyTab.dispatch('click')
  // Three awaits, not one: click -> effect -> fetch -> setState -> rerender is a
  // chain of promise turns, and a single tick lands before the last one.
  await tick()
  await tick()
  await tick()
  const text = allText(slot.lastTree).join(' | ')
  record('history tab loads the trail from the host', bridge.calls.some((c) => c.method === 'panel' && c.args?.op === 'history'), 'client never asked for history')
  record('history asks the host to verify each entry against disk', bridge.calls.some((c) => c.method === 'panel' && c.args?.op === 'history' && c.args?.args?.verify === true), 'client never asked for verification — badges would be write-time guesses')
  record('history shows which rule the edit addressed', text.includes('SC101'), 'rule id missing from the trail')
  record('history shows the before/after diff', text.includes('os.system(cmd)') && text.includes('subprocess.run'), 'diff missing — the trail does not show what changed')
  record('history shows the backup that makes it reversible', text.includes('.bak'), 'backup path missing')
  record('a reverted entry is labelled instead of reading as current', text.includes('已被撤回'), 'reverted badge missing — a stale record would look like truth')
  record('a current entry carries no warning badge', !text.includes('文件已再次改动'), 'stale badge shown for an entry that is still current')
}

/* ---- 7a. live monitoring is the default view, with no button pressed ---- */
//
// The complaint this tab exists for: "it still needs me to click 开始扫描". So the
// assertions are about what is on screen *before* any click — the card opens on
// the live tab, the Host was asked for the trail, and the trail shows what the
// gate actually decided. A button would make all of this true only after a click,
// which is exactly the failure mode being fixed.
const liveTab = findAll(slot.lastTree, 'dsh-cq-tab').find((node) => allText(node).join('') === '实时监测') || null
record('live tab is offered in the card', Boolean(liveTab), `tabs=${findAll(slot.lastTree, 'dsh-cq-tab').map((n) => allText(n).join('')).join('/')}`)
record(
  'the card asks the host for the live trail without being clicked',
  bridge.calls.some((call) => call.method === 'live-log'),
  'client never asked for live-log — the tab would have to guess',
)
record(
  'the live trail is scoped to this conversation',
  bridge.calls.filter((call) => call.method === 'live-log').every((call) => call.sessionId === 'session-1'),
  JSON.stringify(bridge.calls.filter((call) => call.method === 'live-log').map((call) => call.sessionId)),
)

liveTab?.dispatch('click')
await tick()
const liveText = allText(slot.lastTree).join(' | ')
record('live tab reports that monitoring is running', liveText.includes('监控中'), 'no 监控中 status — the user cannot tell watching from stopped')
record('live tab shows how many writes were inspected', liveText.includes('已检查') && liveText.includes('2'), 'inspected counter missing')
record('live tab shows the hit counter', liveText.includes('命中'), 'hit counter missing')
record(
  'live tab names the workspace being watched',
  liveText.includes('C:/work/demo'),
  'workspace path missing — "watching what?" has no answer',
)
record(
  'a blocked write appears in the trail with its rule',
  liveText.includes('已拦截') && liveText.includes('SC101'),
  'the blocked entry is not on screen',
)
record(
  'a passing write is listed too, so silence is not mistaken for success',
  liveText.includes('通过') && liveText.includes('src/a.py'),
  'the SAFE entry is missing',
)
record(
  'the trail is newest first',
  liveText.indexOf('src/b.py') >= 0 && liveText.indexOf('src/b.py') < liveText.indexOf('src/a.py'),
  'the newest entry is not at the top',
)

/* ---- 7b. a clean project must say so, not blame a filter ---- */
//
// The user's question after a scan of a healthy repository is "so is it fine?".
// The table used to answer "没有符合条件的结果" whenever it had no rows — which
// describes a filter that hid results, and reads as if something was found but
// not shown. A SAFE scan with zero findings has to say 未发现问题.
const scanTab = findAll(slot.lastTree, 'dsh-cq-tab').find((node) => allText(node).join('') === '扫描结果') || null
record('scan tab is offered in the card', Boolean(scanTab), `tabs=${findAll(slot.lastTree, 'dsh-cq-tab').map((n) => allText(n).join('')).join('/')}`)
if (scanTab) {
  scanTab.dispatch('click')
  await tick()
  const runButton = findAll(slot.lastTree, 'dsh-cq-btn2').find((node) => allText(node).join('') === '开始扫描') || null
  record('scan tab offers a run button', Boolean(runButton), 'no 开始扫描 button in the scan tab')
  if (runButton) {
    runButton.dispatch('click')
    for (let round = 0; round < 4; round += 1) await tick()
    const scanText = allText(slot.lastTree).join(' | ')
    record(
      'a clean scan reports no problems instead of an empty filter',
      scanText.includes('未发现问题') && !scanText.includes('没有符合条件的结果'),
      `empty state read: ${scanText.includes('没有符合条件的结果') ? '没有符合条件的结果' : scanText.includes('未发现问题') ? '未发现问题' : '(missing)'}`,
    )
    record('a clean scan still shows the SAFE verdict and the file count', scanText.includes('SAFE') && scanText.includes('42'), 'verdict or file count missing from a clean result')
  }
}

/* ---- 8. the master switch ---- */
// The per-session switch answers "may this window block writes?". The master
// switch answers "do I want this tool at all?", is global, and is the one that
// governs the automatic session-created audit. It has to be reachable from the
// card, not only from a profile patch file.
const phaseOf = () => findButton(slot.lastTree)?.attributes?.get('data-phase')
const findSwitch = (label) => findAll(slot.lastTree, 'dsh-cq-switch').find((node) => node.getAttribute('aria-label') === label) || null
const masterSwitch = findSwitch('总开关')
record('master switch is rendered in the footer', Boolean(masterSwitch), 'no switch labelled 总开关')
record('master switch starts on', masterSwitch?.getAttribute('data-on') === 'true', String(masterSwitch?.getAttribute('data-on')))

const armCallsBefore = bridge.calls.filter((call) => call.method === 'arm').length
masterSwitch?.dispatch('click')
await tick()
await tick()
record(
  'master switch calls the host instead of only repainting locally',
  bridge.calls.some((call) => call.method === 'master' && call.args?.enabled === false),
  JSON.stringify(bridge.calls.filter((call) => call.method === 'master')),
)
record('turning the master off paints the icon disarmed', phaseOf() === 'disarmed', String(phaseOf()))
const sessionSwitch = findSwitch('写入拦截')
record(
  'turning the master off disables the per-session switch',
  sessionSwitch?.getAttribute('disabled') === 'true',
  String(sessionSwitch?.getAttribute('disabled')),
)
sessionSwitch?.dispatch('click')
await tick()
record(
  'a click on the disabled per-session switch does not silently re-arm interception',
  bridge.calls.filter((call) => call.method === 'arm').length === armCallsBefore,
  'the card sent an arm call while the master was off',
)

/* ---- 7. the card subscribes instead of polling ---- */
//
// The icon used to poll every 1.5s (6s when closed). That is not "live": a block
// landing just after a tick stayed invisible for up to a second and a half, and
// the closed state kept a timer alive forever. The Host now pushes, so these
// checks push a frame the way the server would and look at the icon.
const feeds = globals.sources
record('the card subscribes to the host feed', feeds.length === 1, `${feeds.length} EventSource(s) opened`)
record(
  'the feed is scoped to this conversation',
  (feeds[0]?.url || '').includes('session=session-1'),
  String(feeds[0]?.url),
)
const timersBeforeFeed = globals.timers.length
record(
  'the feed carries no polling timer',
  globals.timers.length === timersBeforeFeed && !globals.timers.some((handle) => handle.repeat),
  `${globals.timers.length} timer(s) still scheduled`,
)

feeds[0].emit({ seq: 1, state: { sessionId: 'session-1', armed: true, phase: 'block', alert: 'block', critical: 1, warning: 0, info: 0, verdict: 'BLOCK' } })
await tick()
record('a pushed block repaints the icon without a request', phaseOf() === 'block', String(phaseOf()))

feeds[0].emit({ seq: 2, state: { sessionId: 'session-1', armed: false, phase: 'disarmed', alert: 'block' } })
await tick()
record('a pushed switch flip is reflected immediately', phaseOf() === 'disarmed', String(phaseOf()))

feeds[0].fail()
await tick()
const offlineText = allText(slot.lastTree).join(' | ')
record('a broken feed is reported rather than looking calm', offlineText.includes('状态未知'), 'the card did not say the feed dropped')

/* ---- 7. a frame for another conversation must not repaint this card ---- */
feeds[0].emit({ seq: 3, state: { sessionId: 'session-2', armed: true, phase: 'clean', alert: '' } })
await tick()
record(
  'a frame from another conversation does not repaint this card',
  phaseOf() !== 'clean',
  `phase=${phaseOf()} — one window's scan painted another window's icon`,
)

/* ---- 8. a config change elsewhere must refresh the open forms ---- */
//
// The rules and allowlists live in files a person edits by hand. Without this the
// card kept showing the rules it read the first time it was opened, so a rule
// someone disabled in the file still looked enabled here — and "looks enabled" is
// how you end up trusting a gate that is not running.
const panelCallsBefore = bridge.calls.filter((c) => c.method === 'panel' && c.args?.op === 'state').length
feeds[0].emit({
  seq: 4,
  state: { sessionId: 'session-1', armed: true, phase: 'idle', alert: '', configRev: 7, historyRev: 1 },
})
await tick()
await tick()
const panelCallsAfter = bridge.calls.filter((c) => c.method === 'panel' && c.args?.op === 'state').length
record(
  'a config change elsewhere re-reads the rules instead of showing stale ones',
  panelCallsAfter > panelCallsBefore,
  `${panelCallsBefore} -> ${panelCallsAfter} panel reads`,
)

// The same counter arriving twice must not cause a second read: a feed that
// replays a frame (or a reconnect that resends the current state) would otherwise
// turn every reconnect into a burst of file reads.
feeds[0].emit({
  seq: 5,
  state: { sessionId: 'session-1', armed: true, phase: 'idle', alert: '', configRev: 7, historyRev: 1 },
})
await tick()
await tick()
record(
  'the same revision does not trigger a second read',
  bridge.calls.filter((c) => c.method === 'panel' && c.args?.op === 'state').length === panelCallsAfter,
  `count moved past ${panelCallsAfter}`,
)

console.log(failures === 0 ? '\nall client checks passed' : `\n${failures} client check(s) failed`)
process.exit(failures === 0 ? 0 : 1)
