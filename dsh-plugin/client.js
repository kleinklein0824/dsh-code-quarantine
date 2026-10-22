/**
 * dsh-code-quarantine — Client half.
 *
 * The Host half (`index.js`) silently guards every write. Silence is correct
 * behaviour but invisible, so this half adds the discoverable entry point: one
 * icon in `conversation.input.right`, next to the model picker and the
 * prompt-enhance button.
 *
 * The icon is the whole status display. Colour carries the meaning:
 *   neutral  armed, nothing scanned yet        amber  scanning, or warnings found
 *   green    last scan came back clean          red    last write was blocked
 *   grey     disarmed
 * Clicking it opens the panel.
 *
 * The panel is not a toy popover: it mirrors the five tabs of the browser panel
 * that ships with the skill (`scripts/panel/index.html`) — 扫描结果 / 规则开关 /
 * 白名单 / 豁免 / AI 复核. It does not re-implement any of them. Every call goes
 * through the Host's `panel` RPC into `scripts/panel_bridge.py`, which drives the
 * same `Panel` object the browser panel and the CLI use. Two copies of the write
 * logic would drift, and a rule switched off in one surface would keep firing in
 * the other.
 *
 * Four rules kept from the harness' own plugin guidance:
 *  - Only host theme tokens colour the chrome; the eye glyph itself is artwork
 *    and inherits `currentColor`.
 *  - The factory is side-effect free; styles and listeners are mounted in
 *    `apply` through `ctx.effect` so unmounting removes them.
 *  - Fail-open: a Host that does not answer leaves the icon neutral and the
 *    panel explaining why, rather than throwing into the slot.
 *  - Text typed by the user never round-trips through `innerHTML`; React's
 *    default escaping is the only sanitiser here, and that is deliberate.
 */
window.__ModuleLoader__.load({
  id: 'dsh-code-quarantine',
  factory(require) {
    const React = require('react')
    const h = React.createElement

    const NS = 'code-quarantine'
    const RPC = '/dsh-code-quarantine/rpc'

    /**
     * Dictionaries live in the bundle rather than in `locale/*.json` because the
     * Client half is a single plain-JS file served as-is; there is no JSON
     * loader in front of it. The `locale/*.json` copies are what the Plugin
     * Manager reads for the marketplace card.
     */
    const DICTS = {
      zh: {
        'button.title': '代码检疫',
        'phase.idle': '待命',
        'phase.scanning': '检测中…',
        'phase.clean': '未发现问题',
        'phase.warn': '有预警',
        'phase.block': '已拦截',
        'phase.error': '检测出错',
        'phase.disarmed': '已停用',
        'panel.title': '代码检疫',
        'panel.subtitle': '写入前拦截 · 全量审计',
        'panel.close': '关闭',
        'panel.offline': '宿主未响应，状态未知。',
        'panel.loading': '载入中…',
        'panel.noScanner': '没找到扫描器。请把 skill 装到 ~/.dsh/skills/dsh-code-quarantine，或在插件配置里写 skillRoot。',
        'tab.scan': '扫描结果',
        'tab.rules': '规则开关',
        'tab.allow': '白名单',
        'tab.ignore': '豁免',
        'tab.ai': 'AI 复核',
        'foot.switch': '写入拦截',
        'foot.threshold': '拦截级别',
        'foot.critical': '仅 CRITICAL',
        'foot.warning': 'CRITICAL + WARNING',
        'foot.reset': '清除提示',
        'scan.modeFull': '全量扫描',
        'scan.modeIncremental': '增量（git 变更）',
        'scan.includeTests': '含测试目录',
        'scan.useLlm': '用 AI 复核',
        'scan.deep': '深度复核',
        'scan.run': '开始扫描',
        'scan.running': '扫描中…',
        'scan.baseline': '生成签名基线',
        'scan.verdict': '判定',
        'scan.empty': '还没有扫描结果，点「开始扫描」。',
        'scan.filter': '过滤规则 / 文件 / 关键词',
        'scan.all': '全部',
        'scan.crit': '仅 CRITICAL',
        'scan.warn': '仅 WARNING',
        'scan.info': '仅 INFO',
        'scan.none': '没有符合条件的结果。',
        'scan.files': '个文件',
        'scan.done': '扫描完成：',
        'scan.failed': '扫描失败：',
        'act.exempt': '豁免',
        'act.ai': '交给 AI',
        'act.edit': '编辑',
        'act.save': '保存这一行',
        'act.cancel': '取消',
        'act.copy': '复制',
        'act.copied': '已复制',
        'act.expand': '展开证据',
        'rules.hint': '关掉的规则完全不参与判定；把 CRITICAL 降级会直接影响是否阻塞写入。',
        'rules.save': '保存配置',
        'rules.saved': '已保存：',
        'rules.loaded': '条规则生效',
        'rules.changed': '已改',
        'rules.dirty': '有未保存的改动',
        'allow.domains': '信任域名',
        'allow.domainsHint': '不判为广告注入',
        'allow.blocked': '黑名单域名',
        'allow.blockedHint': '命中即告警',
        'allow.registries': '私有 registry',
        'allow.registriesHint': 'SC109 放行',
        'allow.cdn': '允许的 CDN',
        'allow.cdnHint': 'AD005 降级为 WARNING',
        'allow.save': '保存白名单',
        'allow.saved': '白名单已保存',
        'ignore.hint': '每行格式：rule_id 路径glob，rule_id 写 * 表示该路径下全部规则。',
        'ignore.save': '保存豁免',
        'ignore.saved': '豁免已保存',
        'ai.hint': '规则抓结构，模型抓语义。没有密钥时这一层完全跳过，报告里会写明「未启用」。',
        'ai.provider': '接口协议',
        'ai.base': 'Base URL',
        'ai.model': '模型',
        'ai.keyEnv': '密钥环境变量名',
        'ai.key': '临时密钥（明文写入配置）',
        'ai.maxChars': '单文件最大字符',
        'ai.timeout': '请求超时（秒）',
        'ai.maxCalls': '单次扫描调用上限',
        'ai.enabled': '启用 AI 复核',
        'ai.deep': '深度复核（更贵）',
        'ai.test': '测试连接',
        'ai.testing': '测试中…',
        'ai.save': '保存',
        'ai.saved': 'AI 配置已保存',
        'ai.hostModel': '当前对话模型',
        'ai.notConfigured': '未配置完整（需要 base_url + model + 密钥）',
        'ai.ready': '已配置',
        'ai.keyReady': '密钥',
        'ai.source': '来源',
        'save.failed': '保存失败：',
        'common.ok': '完成',
        'tab.history': '修复历史',
        'history.hint': '每次「保存这一行」都会记一条：改前、改后、对应规则、备份路径、改完还剩几条。',
        'history.empty': '还没有改动记录。修复一条问题后，这里会留下可回溯的凭证。',
        'history.total': '共 %d 条记录',
        'history.kept': '只显示最近 %d 条',
        'history.rule': '规则',
        'history.remaining': '改后剩余',
        'history.remainingNone': '该文件已无问题',
        'history.backup': '备份',
        'history.line': '第 %d 行',
        'history.reload': '刷新',
        'history.loadFailed': '读取历史失败：',
        'history.status.current': '仍是当前内容',
        'history.status.reverted': '已被撤回',
        'history.status.stale': '文件已再次改动',
        'history.status.gone': '文件已不存在',
        'history.status.unknown': '无法核对',
        'history.verified': '已核对磁盘',
      },
      en: {
        'button.title': 'Code quarantine',
        'phase.idle': 'Standing by',
        'phase.scanning': 'Scanning…',
        'phase.clean': 'Clean',
        'phase.warn': 'Warnings',
        'phase.block': 'Blocked',
        'phase.error': 'Scan failed',
        'phase.disarmed': 'Disabled',
        'panel.title': 'Code quarantine',
        'panel.subtitle': 'Blocks writes · full audits',
        'panel.close': 'Close',
        'panel.offline': 'Host is not responding; state unknown.',
        'panel.loading': 'Loading…',
        'panel.noScanner': 'No scanner found. Install the skill into ~/.dsh/skills/dsh-code-quarantine or set skillRoot in the plugin config.',
        'tab.scan': 'Findings',
        'tab.rules': 'Rules',
        'tab.allow': 'Allowlist',
        'tab.ignore': 'Exemptions',
        'tab.ai': 'AI review',
        'foot.switch': 'Block writes',
        'foot.threshold': 'Block on',
        'foot.critical': 'CRITICAL only',
        'foot.warning': 'CRITICAL + WARNING',
        'foot.reset': 'Clear alert',
        'scan.modeFull': 'Full scan',
        'scan.modeIncremental': 'Incremental (git)',
        'scan.includeTests': 'Include tests',
        'scan.useLlm': 'AI review',
        'scan.deep': 'Deep review',
        'scan.run': 'Run scan',
        'scan.running': 'Scanning…',
        'scan.baseline': 'Write signature baseline',
        'scan.verdict': 'Verdict',
        'scan.empty': 'No scan yet — press “Run scan”.',
        'scan.filter': 'Filter rule / file / keyword',
        'scan.all': 'All',
        'scan.crit': 'CRITICAL only',
        'scan.warn': 'WARNING only',
        'scan.info': 'INFO only',
        'scan.none': 'Nothing matches the filter.',
        'scan.files': 'files',
        'scan.done': 'Scan finished: ',
        'scan.failed': 'Scan failed: ',
        'act.exempt': 'Exempt',
        'act.ai': 'Ask AI',
        'act.edit': 'Edit',
        'act.save': 'Save this line',
        'act.cancel': 'Cancel',
        'act.copy': 'Copy',
        'act.copied': 'Copied',
        'act.expand': 'Show evidence',
        'rules.hint': 'A disabled rule takes no part in the verdict; lowering CRITICAL changes whether writes are blocked.',
        'rules.save': 'Save config',
        'rules.saved': 'Saved: ',
        'rules.loaded': 'rules in effect',
        'rules.changed': 'changed',
        'rules.dirty': 'Unsaved changes',
        'allow.domains': 'Trusted domains',
        'allow.domainsHint': 'never flagged as ad injection',
        'allow.blocked': 'Blocked domains',
        'allow.blockedHint': 'any hit is reported',
        'allow.registries': 'Private registries',
        'allow.registriesHint': 'SC109 passes',
        'allow.cdn': 'Allowed CDNs',
        'allow.cdnHint': 'AD005 downgraded to WARNING',
        'allow.save': 'Save allowlist',
        'allow.saved': 'Allowlist saved',
        'ignore.hint': 'One per line: rule_id path-glob. Use * as the rule_id to exempt every rule on that path.',
        'ignore.save': 'Save exemptions',
        'ignore.saved': 'Exemptions saved',
        'ai.hint': 'Rules catch structure, the model catches meaning. With no key this layer is skipped entirely and the report says so.',
        'ai.provider': 'Protocol',
        'ai.base': 'Base URL',
        'ai.model': 'Model',
        'ai.keyEnv': 'Key env var',
        'ai.key': 'Temporary key (stored in clear)',
        'ai.maxChars': 'Max chars per file',
        'ai.timeout': 'Timeout (s)',
        'ai.maxCalls': 'Max calls per scan',
        'ai.enabled': 'Enable AI review',
        'ai.deep': 'Deep review (costlier)',
        'ai.test': 'Test connection',
        'ai.testing': 'Testing…',
        'ai.save': 'Save',
        'ai.saved': 'AI config saved',
        'ai.hostModel': 'Current chat model',
        'ai.notConfigured': 'Incomplete (needs base_url + model + key)',
        'ai.ready': 'Configured',
        'ai.keyReady': 'key',
        'ai.source': 'source',
        'save.failed': 'Save failed: ',
        'common.ok': 'Done',
        'tab.history': 'Fix history',
        'history.hint': 'Every "save this line" leaves a record: before, after, which rule, backup path, and what is left.',
        'history.empty': 'No edits recorded yet. Fix one finding and the evidence trail starts here.',
        'history.total': '%d records',
        'history.kept': 'showing the latest %d',
        'history.rule': 'rule',
        'history.remaining': 'left',
        'history.remainingNone': 'file is clean now',
        'history.backup': 'backup',
        'history.line': 'line %d',
        'history.reload': 'Refresh',
        'history.loadFailed': 'Could not read history: ',
        'history.status.current': 'still current',
        'history.status.reverted': 'reverted',
        'history.status.stale': 'file changed again',
        'history.status.gone': 'file gone',
        'history.status.unknown': 'unverified',
        'history.verified': 'checked on disk',
      },
    }

    /**
     * Localised text with a bundled fallback, so a missing dictionary never
     * blanks the UI. The renderer hands slot entries a `t` bound to the
     * namespace declared on the registration; when it is absent (older host, or
     * a dictionary that has not registered yet) the bundled copy is used.
     */
    function makeT(props) {
      const dict = () => {
        const locale = props?.locale
        const active = String(
          (locale && typeof locale.getLocale === 'function' ? locale.getLocale()?.active : '') || '',
        )
        return DICTS[active] || DICTS[active.slice(0, 2)] || DICTS.zh
      }
      if (typeof props?.t === 'function') {
        return (key) => {
          try {
            const value = props.t(key)
            if (typeof value === 'string' && value && value !== key) return value
          } catch {
            /* fall through to the bundled copy */
          }
          return dict()[key] || key
        }
      }
      return (key) => dict()[key] || key
    }

    const EYE = h(
      'svg',
      {
        viewBox: '0 0 64 64',
        width: 16,
        height: 16,
        'aria-hidden': true,
        focusable: 'false',
        style: { display: 'block', flex: 'none' },
      },
      h('path', {
        d: 'M6 30c9-11 27-13 40-4 3 2 5 4 7 7-3 5-8 9-14 11-11 4-24 1-31-9a20 20 0 0 1-2-5z',
        fill: 'none',
        stroke: 'currentColor',
        strokeWidth: 4.2,
        strokeLinejoin: 'round',
      }),
      h('circle', { cx: 30, cy: 31, r: 6.4, fill: 'none', stroke: 'currentColor', strokeWidth: 4.2 }),
      h('path', {
        d: 'M17 15c5-5 15-6 23-2M43 40c4 4 7 8 9 12',
        fill: 'none',
        stroke: 'currentColor',
        strokeWidth: 4.2,
        strokeLinecap: 'round',
      }),
    )

    const CSS = [
      /* The icon is the status light: colour is the signal, not decoration. */
      '.dsh-cq-btn{position:relative;display:inline-flex;align-items:center;justify-content:center;',
      'width:28px;height:28px;padding:0;border:none;border-radius:8px;background:transparent;',
      'cursor:pointer;transition:background-color .15s ease,color .2s ease}',
      '.dsh-cq-btn:hover{background:var(--dsw-alias-bg-layer-2)}',
      '.dsh-cq-btn:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:1px}',
      '.dsh-cq-btn[data-phase="idle"]{color:var(--dsw-alias-label-secondary)}',
      '.dsh-cq-btn[data-phase="disarmed"]{color:var(--dsw-alias-state-idle-primary);opacity:.7}',
      '.dsh-cq-btn[data-phase="scanning"]{color:var(--dsw-alias-state-warn-primary);animation:dsh-cq-pulse 1.1s ease-in-out infinite}',
      '.dsh-cq-btn[data-phase="clean"]{color:var(--dsw-alias-state-success-primary)}',
      '.dsh-cq-btn[data-phase="warn"]{color:var(--dsw-alias-state-warn-primary)}',
      '.dsh-cq-btn[data-phase="block"]{color:var(--dsw-alias-state-error-primary)}',
      '.dsh-cq-btn[data-phase="error"]{color:var(--dsw-alias-state-error-primary)}',
      /* A dot in the corner keeps the state readable at 16px, where hue alone is weak. */
      '.dsh-cq-dot{position:absolute;right:3px;bottom:3px;width:6px;height:6px;border-radius:50%;',
      'background:currentColor;box-shadow:0 0 0 1.5px var(--dsw-alias-bg-base)}',
      '.dsh-cq-btn[data-phase="idle"] .dsh-cq-dot,.dsh-cq-btn[data-phase="disarmed"] .dsh-cq-dot{display:none}',
      '@keyframes dsh-cq-pulse{0%,100%{opacity:1}50%{opacity:.45}}',

      /* Panel shell */
      '.dsh-cq-card{position:fixed;z-index:2147483000;width:432px;max-width:calc(100vw - 24px);',
      'display:flex;flex-direction:column;max-height:min(74vh,620px);',
      'border-radius:14px;border:1px solid var(--dsw-alias-border-l1);background:var(--dsw-alias-bg-overlay);',
      'box-shadow:0 18px 42px rgba(0,0,0,.28);color:var(--dsw-alias-label-primary);',
      'font-size:12.5px;line-height:1.5;font-family:inherit}',
      '.dsh-cq-head{display:flex;align-items:flex-start;gap:8px;padding:12px 14px 8px}',
      '.dsh-cq-head svg{color:var(--dsw-alias-label-secondary);margin-top:1px}',
      '.dsh-cq-title{font-size:13px;font-weight:650;letter-spacing:.2px}',
      '.dsh-cq-sub{color:var(--dsw-alias-label-secondary);font-size:11.5px}',
      '.dsh-cq-target{color:var(--dsw-alias-label-secondary);font-size:10.5px;margin-top:3px;max-width:196px;'
        + 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;opacity:.85;direction:rtl;text-align:left}',
      '.dsh-cq-x{margin-left:auto;border:none;background:transparent;color:var(--dsw-alias-label-secondary);',
      'cursor:pointer;font-size:15px;line-height:1;padding:2px 4px;border-radius:6px}',
      '.dsh-cq-x:hover{background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-primary)}',

      /* Tabs mirror the browser panel's five views */
      '.dsh-cq-tabs{display:flex;gap:2px;padding:0 10px;border-bottom:1px solid var(--dsw-alias-border-l1)}',
      '.dsh-cq-tab{border:none;background:transparent;color:var(--dsw-alias-label-secondary);cursor:pointer;',
      'padding:7px 9px;font-size:12px;font-family:inherit;border-bottom:2px solid transparent;white-space:nowrap}',
      '.dsh-cq-tab:hover{color:var(--dsw-alias-label-primary)}',
      '.dsh-cq-tab[data-active="true"]{color:var(--dsw-alias-brand-primary);border-bottom-color:var(--dsw-alias-brand-primary);font-weight:650}',

      '.dsh-cq-body{overflow:auto;padding:12px 14px;flex:1;min-height:0}',
      '.dsh-cq-foot{display:flex;align-items:center;gap:10px;padding:9px 14px 11px;',
      'border-top:1px solid var(--dsw-alias-border-l1);background:var(--dsw-alias-bg-layer-1);',
      'border-radius:0 0 14px 14px}',

      /* Generic controls */
      '.dsh-cq-row{display:flex;align-items:center;gap:8px}',
      '.dsh-cq-row+.dsh-cq-row{margin-top:8px}',
      '.dsh-cq-label{color:var(--dsw-alias-label-secondary);white-space:nowrap}',
      '.dsh-cq-spacer{flex:1}',
      '.dsh-cq-btn2{border:1px solid var(--dsw-alias-border-l1);background:var(--dsw-alias-bg-layer-2);',
      'color:var(--dsw-alias-label-primary);border-radius:8px;padding:5px 10px;font-size:11.5px;',
      'font-family:inherit;cursor:pointer;white-space:nowrap}',
      '.dsh-cq-btn2:hover{background:var(--dsw-alias-bg-layer-1)}',
      '.dsh-cq-btn2:disabled{opacity:.55;cursor:default}',
      '.dsh-cq-btn2.primary{background:var(--dsw-alias-brand-primary);border-color:var(--dsw-alias-brand-primary);',
      'color:var(--dsw-alias-bg-base);font-weight:650}',
      '.dsh-cq-btn2.tiny{padding:2px 7px;font-size:11px;border-radius:6px}',
      '.dsh-cq-select,.dsh-cq-input{border:1px solid var(--dsw-alias-border-l1);border-radius:8px;',
      'background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-primary);font-size:11.5px;',
      'padding:4px 7px;font-family:inherit;min-width:0}',
      '.dsh-cq-input{width:100%}',
      '.dsh-cq-area{width:100%;min-height:88px;resize:vertical;border:1px solid var(--dsw-alias-border-l1);',
      'border-radius:8px;background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-primary);',
      'font-size:11.5px;line-height:1.6;padding:7px 9px;font-family:ui-monospace,Consolas,monospace;box-sizing:border-box}',
      '.dsh-cq-check{display:inline-flex;align-items:center;gap:5px;color:var(--dsw-alias-label-secondary);cursor:pointer;font-size:11.5px}',
      '.dsh-cq-field{display:flex;flex-direction:column;gap:4px;margin-bottom:9px}',
      '.dsh-cq-field>span{color:var(--dsw-alias-label-secondary);font-size:11px}',
      '.dsh-cq-hint{color:var(--dsw-alias-label-secondary);font-size:11px;line-height:1.6;margin:0 0 9px}',

      /* The switch borrows the status colour so on/off reads at a glance. */
      '.dsh-cq-switch{position:relative;width:34px;height:19px;border-radius:19px;border:none;padding:0;',
      'cursor:pointer;background:var(--dsw-alias-state-idle-primary);transition:background-color .18s ease;flex:none}',
      '.dsh-cq-switch[data-on="true"]{background:var(--dsw-alias-state-success-primary)}',
      '.dsh-cq-switch::after{content:"";position:absolute;top:2.5px;left:2.5px;width:14px;height:14px;',
      'border-radius:50%;background:var(--dsw-alias-bg-base);transition:transform .18s ease}',
      '.dsh-cq-switch[data-on="true"]::after{transform:translateX(15px)}',
      '.dsh-cq-switch:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:2px}',

      /* Verdict badge + counters */
      '.dsh-cq-verdict{display:inline-flex;align-items:center;gap:5px;padding:2px 9px;border-radius:999px;',
      'font-size:11.5px;font-weight:650;border:1px solid transparent}',
      '.dsh-cq-verdict[data-v="BLOCK"]{color:var(--dsw-alias-state-error-primary);background:var(--dsw-alias-bg-layer-2)}',
      '.dsh-cq-verdict[data-v="REVIEW"]{color:var(--dsw-alias-state-warn-primary);background:var(--dsw-alias-bg-layer-2)}',
      '.dsh-cq-verdict[data-v="SAFE"]{color:var(--dsw-alias-state-success-primary);background:var(--dsw-alias-bg-layer-2)}',
      '.dsh-cq-verdict[data-v="ERROR"]{color:var(--dsw-alias-state-error-primary);background:var(--dsw-alias-bg-layer-2)}',
      '.dsh-cq-counts{display:flex;gap:10px;color:var(--dsw-alias-label-secondary);font-size:11.5px;margin-left:auto}',
      '.dsh-cq-counts b{font-weight:650}',
      '.dsh-cq-crit b{color:var(--dsw-alias-state-error-primary)}',
      '.dsh-cq-warn b{color:var(--dsw-alias-state-warn-primary)}',
      '.dsh-cq-ok b{color:var(--dsw-alias-state-success-primary)}',

      /* Findings list */
      '.dsh-cq-chips{display:flex;gap:5px;flex-wrap:wrap;margin:9px 0}',
      '.dsh-cq-chip{border:1px solid var(--dsw-alias-border-l1);background:transparent;border-radius:999px;',
      'padding:2px 9px;font-size:11px;color:var(--dsw-alias-label-secondary);cursor:pointer;font-family:inherit}',
      '.dsh-cq-chip[data-active="true"]{background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-primary);font-weight:650}',
      '.dsh-cq-find{border-top:1px solid var(--dsw-alias-border-l2);padding:8px 0}',
      '.dsh-cq-find:first-child{border-top:none}',
      '.dsh-cq-find-top{display:flex;align-items:baseline;gap:6px;flex-wrap:wrap}',
      '.dsh-cq-sev{font-size:10.5px;font-weight:700;letter-spacing:.3px}',
      '.dsh-cq-sev[data-s="CRITICAL"]{color:var(--dsw-alias-state-error-primary)}',
      '.dsh-cq-sev[data-s="WARNING"]{color:var(--dsw-alias-state-warn-primary)}',
      '.dsh-cq-sev[data-s="INFO"]{color:var(--dsw-alias-label-secondary)}',
      '.dsh-cq-rule{font-family:ui-monospace,Consolas,monospace;font-size:11px;color:var(--dsw-alias-label-secondary)}',
      '.dsh-cq-where{font-family:ui-monospace,Consolas,monospace;font-size:11px;color:var(--dsw-alias-label-secondary);',
      'margin-left:auto;white-space:nowrap}',
      '.dsh-cq-msg{margin-top:3px}',
      '.dsh-cq-ev{margin-top:5px;padding:6px 8px;border-radius:6px;background:var(--dsw-alias-bg-layer-2);',
      'font-family:ui-monospace,Consolas,monospace;font-size:11px;white-space:pre-wrap;word-break:break-all;',
      'color:var(--dsw-alias-label-secondary)}',
      '.dsh-cq-acts{display:flex;gap:4px;margin-top:5px;flex-wrap:wrap}',
      '.dsh-cq-empty{color:var(--dsw-alias-label-secondary);font-size:11.5px;padding:10px 0}',

      /* History tab: one block per edit, diff lines kept monospace so a
         whitespace-only fix is still visible. */
      '.dsh-cq-meta{font-size:11px;color:var(--dsw-alias-label-secondary)}',
      '.dsh-cq-hist{padding:7px 0;border-top:1px solid var(--dsw-alias-border-l2)}',
      '.dsh-cq-hist:first-of-type{border-top:none}',
      '.dsh-cq-hist-clock{font-size:11px;color:var(--dsw-alias-label-secondary);flex:none;width:52px}',
      '.dsh-cq-diff{margin-top:4px;padding:5px 7px;border-radius:6px;background:var(--dsw-alias-bg-layer-2);',
      'font-family:ui-monospace,Consolas,monospace;font-size:10.5px;line-height:1.55;',
      'white-space:pre-wrap;word-break:break-all}',
      '.dsh-cq-diff-before{color:var(--dsw-alias-state-error-primary);opacity:.85}',
      '.dsh-cq-diff-after{color:var(--dsw-alias-state-success-primary)}',
      '.dsh-cq-status{flex:none;margin-left:6px;padding:0 5px;border-radius:5px;font-size:9.5px;',
      'line-height:15px;border:1px solid currentColor;opacity:.9}',
      '.dsh-cq-status-reverted{color:var(--dsw-alias-state-warn-primary)}',
      '.dsh-cq-status-stale{color:var(--dsw-alias-state-warn-primary)}',
      '.dsh-cq-status-gone{color:var(--dsw-alias-label-secondary)}',
      '.dsh-cq-status-unknown{color:var(--dsw-alias-label-secondary)}',
      '.dsh-cq-hist[data-status="reverted"] .dsh-cq-diff-after{opacity:.45}',
      '.dsh-cq-hist[data-status="stale"] .dsh-cq-diff-after{opacity:.45}',

      /* Rules tab */
      '.dsh-cq-cat{font-size:11px;color:var(--dsw-alias-label-secondary);font-weight:650;',
      'letter-spacing:.4px;margin:12px 0 5px}',
      '.dsh-cq-cat:first-child{margin-top:0}',
      '.dsh-cq-rule-row{display:flex;align-items:center;gap:8px;padding:5px 0;border-top:1px solid var(--dsw-alias-border-l2)}',
      '.dsh-cq-rule-row:first-of-type{border-top:none}',
      '.dsh-cq-rule-row[data-off="true"]{opacity:.5}',
      '.dsh-cq-rule-id{font-family:ui-monospace,Consolas,monospace;font-size:11px;font-weight:650;width:52px;flex:none}',
      '.dsh-cq-rule-name{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}',
      '.dsh-cq-rule-flag{font-size:10.5px;color:var(--dsw-alias-state-warn-primary);width:26px;flex:none}',
    ].join('')

    /** One style element per page; the disposer removes it on unload. */
    function insertStyles() {
      const element = document.createElement('style')
      element.setAttribute('data-dsh-plugin', NS)
      element.textContent = CSS
      document.head.appendChild(element)
      return () => {
        element.remove()
      }
    }

    /**
     * Which colour family the icon shows.
     *
     * The sticky `alert` wins over the momentary `phase`: a block followed by one
     * harmless write must not paint the icon green while the rejected payload is
     * still on the user's clipboard. Only an explicit reset or a clean full audit
     * clears the alert on the host side.
     */
    function phaseOf(state) {
      if (!state) return 'idle'
      if (state.armed === false) return 'disarmed'
      if (state.alert === 'block') return 'block'
      if (state.alert === 'warn') return 'warn'
      const phase = String(state.phase || 'idle')
      return phase === 'idle' || phase === 'scanning' || phase === 'clean' || phase === 'warn' || phase === 'block' || phase === 'error'
        ? phase
        : 'idle'
    }

    /**
     * Send one request to the Host, scoped to this conversation.
     *
     * `sessionId` travels with every call. The Host keeps one gate state per
     * conversation, and without the id it cannot tell which one this window is
     * asking about — it would answer with whichever state it happened to create
     * first, so a switch flipped in one window would appear in all of them.
     */
    function callHost(method, args, target, sessionId) {
      return fetch(RPC, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          method,
          args: args || {},
          target: target || undefined,
          sessionId: sessionId || undefined,
        }),
      })
        .then((response) => (response.ok ? response.json() : { ok: false }))
        .catch(() => ({ ok: false, offline: true }))
    }

    /**
     * One bridge call: `op` is a `panel_bridge.py` method name.
     *
     * `target` is the project directory. The Host cannot guess it — its own
     * `process.cwd()` is the profile directory, so a scan started from the card
     * without a target audited `~/.dsh/profiles/<name>` and reported six files as
     * clean. The Session knows the workspace it is attached to; that is the only
     * directory the user can be looking at while clicking this icon.
     */
    function callPanel(op, args, target, sessionId) {
      return callHost('panel', { op, args: args || {}, target: target || undefined }, target, sessionId)
    }

    function timeLabel(timestamp) {
      if (!timestamp) return ''
      try {
        return new Date(timestamp).toLocaleTimeString()
      } catch {
        return ''
      }
    }

    /** Small building blocks, kept dumb so each tab reads like markup. */
    const Row = (props) => h('div', { className: 'dsh-cq-row' }, props.children)
    const Hint = (props) => h('p', { className: 'dsh-cq-hint' }, props.children)
    const Button = (props) =>
      h(
        'button',
        {
          type: 'button',
          className: `dsh-cq-btn2${props.variant ? ` ${props.variant}` : ''}`,
          disabled: props.disabled,
          title: props.title,
          onClick: props.onClick,
        },
        props.children,
      )

    /** Field wrapper: label above control, so long Chinese labels never squeeze. */
    function Field(props) {
      return h(
        'label',
        { className: 'dsh-cq-field' },
        h('span', null, props.label),
        props.children,
      )
    }

    const SEVERITIES = ['CRITICAL', 'WARNING', 'INFO']
    const CATEGORY_NAMES = {
      ad_injection: '第一层 · 广告注入',
      supply_chain: '第二层 · 供应链投毒',
      architecture_deviation: '第三层 · 架构偏离',
    }
    const CATEGORY_ORDER = ['ad_injection', 'supply_chain', 'architecture_deviation']

    /* ------------------------------------------------------------------ tabs */

    function ScanTab({ t, panel, onScan, scanning, onExempt, onPrompt, onReveal, onEditLine }) {
      const [sev, setSev] = React.useState('ALL')
      const [text, setText] = React.useState('')
      const [expanded, setExpanded] = React.useState(-1)
      const [mode, setMode] = React.useState('full')
      const [tests, setTests] = React.useState(false)
      const [llm, setLlm] = React.useState(false)
      const [deep, setDeep] = React.useState(false)

      const data = panel && panel.scan
      const summary = (data && data.summary) || {}
      const counts = summary.severity || {}
      const findings = (data && data.findings) || []
      const rows = findings.filter((f) => {
        if (sev !== 'ALL' && f.severity !== sev) return false
        if (!text) return true
        const hay = `${f.rule_id} ${f.file} ${f.message} ${f.evidence || ''}`.toLowerCase()
        return hay.includes(text.toLowerCase())
      })

      return h(
        'div',
        null,
        h(
          Row,
          null,
          h(
            'select',
            {
              className: 'dsh-cq-select',
              value: mode,
              onChange: (e) => setMode(e.target.value),
            },
            h('option', { value: 'full' }, t('scan.modeFull')),
            h('option', { value: 'incremental' }, t('scan.modeIncremental')),
          ),
          h(
            'label',
            { className: 'dsh-cq-check' },
            h('input', { type: 'checkbox', checked: tests, onChange: (e) => setTests(e.target.checked) }),
            t('scan.includeTests'),
          ),
          h(
            'label',
            { className: 'dsh-cq-check' },
            h('input', { type: 'checkbox', checked: llm, onChange: (e) => setLlm(e.target.checked) }),
            t('scan.useLlm'),
          ),
          h('div', { className: 'dsh-cq-spacer' }),
          h(Button, { variant: 'primary', disabled: scanning, onClick: () => onScan({ mode, include_tests: tests, use_llm: llm, llm_deep: deep }) },
            scanning ? t('scan.running') : t('scan.run')),
        ),
        h(
          Row,
          { style: { marginTop: 10 } },
          h(
            'span',
            { className: 'dsh-cq-verdict', 'data-v': (data && data.verdict) || 'SAFE' },
            (data && data.verdict) || '—',
          ),
          h(
            'div',
            { className: 'dsh-cq-counts' },
            h('span', { className: 'dsh-cq-crit' }, 'C ', h('b', null, counts.CRITICAL || 0)),
            h('span', { className: 'dsh-cq-warn' }, 'W ', h('b', null, counts.WARNING || 0)),
            h('span', { className: 'dsh-cq-ok' }, 'I ', h('b', null, counts.INFO || 0)),
            h('span', null, `${summary.scanned_files || 0} ${t('scan.files')}`),
          ),
        ),
        h(
          'div',
          { className: 'dsh-cq-chips' },
          ['ALL', 'CRITICAL', 'WARNING', 'INFO'].map((key) =>
            h(
              'button',
              {
                key,
                type: 'button',
                className: 'dsh-cq-chip',
                'data-active': String(sev === key),
                onClick: () => setSev(key),
              },
              key === 'ALL'
                ? t('scan.all')
                : key === 'CRITICAL'
                  ? t('scan.crit')
                  : key === 'WARNING'
                    ? t('scan.warn')
                    : t('scan.info'),
            ),
          ),
          h('input', {
            className: 'dsh-cq-input',
            style: { marginLeft: 'auto', width: 132, flex: 'none' },
            placeholder: t('scan.filter'),
            value: text,
            onChange: (e) => setText(e.target.value),
          }),
        ),
        !data
          ? h('div', { className: 'dsh-cq-empty' }, t('scan.empty'))
          : !rows.length
            ? h('div', { className: 'dsh-cq-empty' }, t('scan.none'))
            : rows.map((f, index) =>
                h(
                  'div',
                  { className: 'dsh-cq-find', key: `${f.rule_id}:${f.file}:${f.line}:${index}` },
                  h(
                    'div',
                    { className: 'dsh-cq-find-top' },
                    h('span', { className: 'dsh-cq-sev', 'data-s': f.severity }, f.severity),
                    h('span', { className: 'dsh-cq-rule' }, f.rule_id),
                    h('span', { className: 'dsh-cq-where' }, `${f.file}:${f.line}`),
                  ),
                  h('div', { className: 'dsh-cq-msg' }, f.message),
                  expanded === index
                    ? h(
                        'div',
                        null,
                        f.evidence ? h('div', { className: 'dsh-cq-ev' }, f.evidence) : null,
                        f.suggestion
                          ? h('div', { className: 'dsh-cq-ev' }, `修复：${f.suggestion}`)
                          : null,
                      )
                    : null,
                  h(
                    'div',
                    { className: 'dsh-cq-acts' },
                    h(
                      Button,
                      { variant: 'tiny', onClick: () => setExpanded(expanded === index ? -1 : index) },
                      t('act.expand'),
                    ),
                    h(Button, { variant: 'tiny', onClick: () => onExempt(f) }, t('act.exempt')),
                    h(Button, { variant: 'tiny', onClick: () => onPrompt(f) }, t('act.ai')),
                    h(Button, { variant: 'tiny', onClick: () => onReveal(f) }, '跳转'),
                    h(Button, { variant: 'tiny', onClick: () => onEditLine(f) }, t('act.edit')),
                  ),
                ),
              ),
      )
    }

    function RulesTab({ t, panel, onSave }) {
      const [edits, setEdits] = React.useState({})
      const rules = (panel && panel.rules) || []
      const groups = {}
      for (const rule of rules) (groups[rule.category] = groups[rule.category] || []).push(rule)
      const order = CATEGORY_ORDER.concat(Object.keys(groups).filter((k) => !CATEGORY_ORDER.includes(k)))
      const dirty = Object.keys(edits).length > 0

      const current = (rule) => edits[rule.id] || { enabled: rule.enabled, severity: rule.severity }
      const patch = (rule, change) =>
        setEdits((previous) => ({
          ...previous,
          [rule.id]: { ...current(rule), ...change },
        }))

      return h(
        'div',
        null,
        h(Hint, null, t('rules.hint')),
        order.map((category) => {
          if (!groups[category]) return null
          return h(
            'div',
            { key: category },
            h('div', { className: 'dsh-cq-cat' }, CATEGORY_NAMES[category] || category),
            groups[category].map((rule) => {
              const view = current(rule)
              const changed = view.severity !== rule.default_severity || view.enabled !== rule.default_enabled
              return h(
                'div',
                { className: 'dsh-cq-rule-row', key: rule.id, 'data-off': String(!view.enabled) },
                h('span', { className: 'dsh-cq-rule-id' }, rule.id),
                h('span', { className: 'dsh-cq-rule-name', title: `${rule.title}\n${rule.message || ''}` }, rule.title),
                h(
                  'select',
                  {
                    className: 'dsh-cq-select',
                    value: view.severity,
                    onChange: (e) => patch(rule, { severity: e.target.value }),
                  },
                  SEVERITIES.map((s) => h('option', { key: s, value: s }, s)),
                ),
                h(
                  'button',
                  {
                    type: 'button',
                    className: 'dsh-cq-switch',
                    'data-on': String(view.enabled),
                    'aria-pressed': String(view.enabled),
                    'aria-label': rule.title,
                    onClick: () => patch(rule, { enabled: !view.enabled }),
                  },
                ),
                h('span', { className: 'dsh-cq-rule-flag' }, changed ? t('rules.changed') : ''),
              )
            }),
          )
        }),
        h(
          Row,
          { style: { marginTop: 12 } },
          dirty ? h('span', { className: 'dsh-cq-hint', style: { margin: 0 } }, t('rules.dirty')) : null,
          h('div', { className: 'dsh-cq-spacer' }),
          h(
            Button,
            {
              variant: 'primary',
              onClick: () => {
                onSave({ rules: edits })
                setEdits({})
              },
            },
            t('rules.save'),
          ),
        ),
      )
    }

    function AllowTab({ t, panel, onSave }) {
      const allow = (panel && panel.allow) || {}
      const [domains, setDomains] = React.useState(null)
      const [blocked, setBlocked] = React.useState(null)
      const [registries, setRegistries] = React.useState(null)
      const [cdn, setCdn] = React.useState(null)

      // Seed from the server on first paint and whenever the tab is remounted
      // with fresh data; a non-null local value means the user has typed.
      const value = (local, key) => (local === null ? (allow[key] || []).join('\n') : local)

      const area = (local, setLocal, key) =>
        h('textarea', {
          className: 'dsh-cq-area',
          spellCheck: false,
          value: value(local, key),
          onChange: (e) => setLocal(e.target.value),
        })

      const collect = () => ({
        domains: value(domains, 'domains').split('\n').map((s) => s.trim()).filter(Boolean),
        blocked_domains: value(blocked, 'blocked_domains').split('\n').map((s) => s.trim()).filter(Boolean),
        registries: value(registries, 'registries').split('\n').map((s) => s.trim()).filter(Boolean),
        cdn_domains: value(cdn, 'cdn_domains').split('\n').map((s) => s.trim()).filter(Boolean),
      })

      return h(
        'div',
        null,
        h(
          Row,
          null,
          h(
            'div',
            { style: { flex: 1, minWidth: 0 } },
            h(Field, { label: `${t('allow.domains')} · ${t('allow.domainsHint')}` }, area(domains, setDomains, 'domains')),
            h(Field, { label: `${t('allow.registries')} · ${t('allow.registriesHint')}` }, area(registries, setRegistries, 'registries')),
          ),
          h(
            'div',
            { style: { flex: 1, minWidth: 0 } },
            h(Field, { label: `${t('allow.blocked')} · ${t('allow.blockedHint')}` }, area(blocked, setBlocked, 'blocked_domains')),
            h(Field, { label: `${t('allow.cdn')} · ${t('allow.cdnHint')}` }, area(cdn, setCdn, 'cdn_domains')),
          ),
        ),
        h(
          Row,
          null,
          h('div', { className: 'dsh-cq-spacer' }),
          h(
            Button,
            {
              variant: 'primary',
              onClick: () => {
                onSave({ allow: collect() })
                setDomains(null)
                setBlocked(null)
                setRegistries(null)
                setCdn(null)
              },
            },
            t('allow.save'),
          ),
        ),
      )
    }

    /**
     * The audit trail for edits made through this card.
     *
     * "一键修复" writes a file in place. Without this tab the only residue is a
     * toast that disappears in two seconds plus a `.bak` whose content nobody can
     * attribute to a rule. The data is append-only on the Host side, so this tab
     * is a read-only view: the evidence has to survive the moment of the fix.
     */
    function HistoryTab({ t, entries, loading, onReload }) {
      if (loading && !entries) return h('div', { className: 'dsh-cq-empty' }, t('panel.loading'))
      const rows = entries || []
      if (!rows.length) {
        return h(
          'div',
          null,
          h(Hint, null, t('history.hint')),
          h('div', { className: 'dsh-cq-empty' }, t('history.empty')),
          h(Row, { style: { marginTop: 10 } }, h(Button, { onClick: onReload }, t('history.reload'))),
        )
      }
      return h(
        'div',
        null,
        h(Hint, null, t('history.hint')),
        h(
          Row,
          { style: { marginBottom: 8 } },
          h('span', { className: 'dsh-cq-meta' }, t('history.total').replace('%d', String(rows.length))),
          h('div', { className: 'dsh-cq-spacer' }),
          h(Button, { onClick: onReload }, t('history.reload')),
        ),
        rows.map((entry, index) =>
          h(
            'div',
            { key: `${entry.iso || ''}-${index}`, className: 'dsh-cq-hist', 'data-status': entry.status || 'unknown' },
            h(
              Row,
              null,
              h('span', { className: 'dsh-cq-hist-clock' }, entry.clock || ''),
              h('span', { className: 'dsh-cq-rule' }, entry.rule_id || '*'),
              h('span', { className: 'dsh-cq-meta' },
                `${entry.file}:${entry.line} · ${t('history.line').replace('%d', String(entry.line || 0))}`),
              // The entry is a snapshot; the file kept moving. A badge is the only
              // thing that keeps a three-day-old record from reading like current
              // truth — otherwise the user chases a fix that is no longer there.
              entry.status && entry.status !== 'current'
                ? h('span', { className: `dsh-cq-status dsh-cq-status-${entry.status}` },
                    t(`history.status.${entry.status}`))
                : null,
            ),
            h('div', { className: 'dsh-cq-diff' },
              h('div', { className: 'dsh-cq-diff-before' }, `- ${entry.before || ''}`),
              h('div', { className: 'dsh-cq-diff-after' }, `+ ${entry.after || ''}`)),
            h(Row, { style: { marginTop: 4 } },
              h('span', { className: 'dsh-cq-meta' },
                entry.remaining > 0
                  ? `${t('history.remaining')}: ${entry.remaining}`
                  : t('history.remainingNone')),
              h('div', { className: 'dsh-cq-spacer' }),
              entry.backup
                ? h('span', { className: 'dsh-cq-meta', title: entry.backup },
                    `${t('history.backup')}: ${entry.backup.split('/').pop()}`)
                : null),
          ),
        ),
      )
    }

    function IgnoreTab({ t, panel, onSave }) {
      const lines = (panel && panel.ignore) || []
      const [text, setText] = React.useState(null)
      const value = text === null ? lines.join('\n') : text
      return h(
        'div',
        null,
        h(Hint, null, t('ignore.hint')),
        h('textarea', {
          className: 'dsh-cq-area',
          style: { minHeight: 200 },
          spellCheck: false,
          value,
          onChange: (e) => setText(e.target.value),
        }),
        h(
          Row,
          { style: { marginTop: 10 } },
          h('div', { className: 'dsh-cq-spacer' }),
          h(
            Button,
            {
              variant: 'primary',
              onClick: () => {
                onSave({ ignore: value.split('\n').map((s) => s.trim()).filter(Boolean) })
                setText(null)
              },
            },
            t('ignore.save'),
          ),
        ),
      )
    }

    function AiTab({ t, panel, onSave, onTest }) {
      const llm = (panel && panel.llm) || {}
      const [form, setForm] = React.useState(null)
      const [testing, setTesting] = React.useState(false)
      const [status, setStatus] = React.useState('')
      const base = form || {
        enabled: llm.enabled !== false,
        provider: llm.provider || 'openai',
        base_url: llm.base_url || '',
        model: llm.model || '',
        api_key_env: llm.api_key_env || 'DSH_QUARANTINE_LLM_API_KEY',
        max_chars: llm.max_chars || 6000,
        timeout: llm.timeout || 30,
        max_calls: llm.max_calls || 20,
        api_key: '',
      }
      const set = (key) => (e) =>
        setForm({ ...base, [key]: e.target.type === 'checkbox' ? e.target.checked : e.target.value })

      const bits = []
      bits.push(llm.ready ? `${t('ai.ready')}：${llm.model || ''}` : t('ai.notConfigured'))
      if (llm.has_key) bits.push(`${t('ai.keyReady')} ${llm.key_hint || ''}`)
      if (llm.source && llm.source !== 'none') bits.push(`${t('ai.source')} ${llm.source}`)

      return h(
        'div',
        null,
        h(Hint, null, t('ai.hint')),
        h(
          Row,
          null,
          h(Field, { label: t('ai.provider') },
            h(
              'select',
              { className: 'dsh-cq-select', value: base.provider, onChange: set('provider'), style: { width: '100%' } },
              h('option', { value: 'openai' }, 'OpenAI 兼容'),
              h('option', { value: 'anthropic' }, 'Anthropic'),
            ),
          ),
          h(Field, { label: t('ai.base') },
            h('input', { className: 'dsh-cq-input', value: base.base_url, onChange: set('base_url'), spellCheck: false }),
          ),
        ),
        h(
          Row,
          null,
          h(Field, { label: t('ai.model') },
            h('input', { className: 'dsh-cq-input', value: base.model, onChange: set('model'), spellCheck: false }),
          ),
          h(Field, { label: t('ai.keyEnv') },
            h('input', { className: 'dsh-cq-input', value: base.api_key_env, onChange: set('api_key_env'), spellCheck: false }),
          ),
        ),
        h(
          Row,
          null,
          h(Field, { label: t('ai.key') },
            h('input', {
              className: 'dsh-cq-input',
              type: 'password',
              value: base.api_key,
              onChange: set('api_key'),
              spellCheck: false,
              autoComplete: 'off',
            }),
          ),
          h(Field, { label: t('ai.timeout') },
            h('input', { className: 'dsh-cq-input', value: base.timeout, onChange: set('timeout'), inputMode: 'numeric' }),
          ),
        ),
        h(
          Row,
          null,
          h(Field, { label: t('ai.maxChars') },
            h('input', { className: 'dsh-cq-input', value: base.max_chars, onChange: set('max_chars'), inputMode: 'numeric' }),
          ),
          h(Field, { label: t('ai.maxCalls') },
            h('input', { className: 'dsh-cq-input', value: base.max_calls, onChange: set('max_calls'), inputMode: 'numeric' }),
          ),
        ),
        h(
          Row,
          { style: { marginBottom: 8 } },
          h(
            'label',
            { className: 'dsh-cq-check' },
            h('input', { type: 'checkbox', checked: base.enabled !== false, onChange: set('enabled') }),
            t('ai.enabled'),
          ),
        ),
        h('div', { className: 'dsh-cq-hint' }, status || bits.join(' · ')),
        llm.host_model ? h('div', { className: 'dsh-cq-hint' }, `${t('ai.hostModel')}：${llm.host_model}`) : null,
        h(
          Row,
          { style: { marginTop: 6 } },
          h('div', { className: 'dsh-cq-spacer' }),
          h(
            Button,
            {
              disabled: testing,
              onClick: () => {
                setTesting(true)
                setStatus('')
                onTest(base).then((result) => {
                  setTesting(false)
                  if (result && result.ok) {
                    setStatus(`连接正常 · ${result.latency_ms || 0}ms · 回复「${result.reply || ''}」`)
                  } else {
                    setStatus(`连接失败：${(result && result.error) || '未知错误'}`)
                  }
                })
              },
            },
            testing ? t('ai.testing') : t('ai.test'),
          ),
          h(Button, { variant: 'primary', onClick: () => onSave({ llm: base }) }, t('ai.save')),
        ),
      )
    }

    /* ---------------------------------------------------------------- button */

    function QuarantineButton(props) {
      const t = makeT(props)
      const [open, setOpen] = React.useState(false)
      const [state, setState] = React.useState(null)
      const [offline, setOffline] = React.useState(false)
      const [tab, setTab] = React.useState('scan')
      const [panel, setPanel] = React.useState(null)
      const [loading, setLoading] = React.useState(false)
      const [scanning, setScanning] = React.useState(false)
      const [toast, setToast] = React.useState('')
      const [anchor, setAnchor] = React.useState({ right: 16, bottom: 64 })
      const [editing, setEditing] = React.useState(null)
      const [history, setHistory] = React.useState(null)
      const [historyLoading, setHistoryLoading] = React.useState(false)
      const rootRef = React.useRef(null)
      // The card is a sibling of the button inside a Fragment, not a child — it has
      // to be positioned `fixed` against the viewport, so it cannot be nested in the
      // composer's inline row. That means `rootRef` alone is not "the panel": an
      // outside-click test that only asks `rootRef.contains(target)` treats every
      // mousedown *inside the card* as an outside click and closes the panel on the
      // first tab switch. Both refs are part of the same surface.
      const cardRef = React.useRef(null)

      // The project this conversation is attached to. `useSessions` is a standard
      // slot prop, so it is always present, but `sessionId` can be undefined on a
      // blank session — hence the optional chaining rather than an assumption.
      //
      // The hook must run unconditionally, every render, in the same order; only
      // the *derivation* below is defensive.
      const sessionRows = props.useSessions((snapshot) => snapshot)
      // Every request carries this so the Host can keep one gate state per
      // conversation. Two windows on two projects are two independent work
      // streams: flipping the switch in one must not disarm the other, and a
      // BLOCK in one must not paint the other's icon red.
      const sessionId = typeof props.sessionId === 'string' ? props.sessionId : ''
      let target = ''
      try {
        const row = sessionRows && props.sessionId ? sessionRows.byId?.[props.sessionId] : undefined
        target = (row && row.cwd) || ''
      } catch {
        target = ''
      }

      const refresh = React.useCallback(() => {
        callHost('state', {}, target, sessionId).then((result) => {
          if (result && result.ok && result.state) {
            setState(result.state)
            setOffline(false)
          } else {
            setOffline(true)
          }
        })
      }, [target, sessionId])

      // Poll while the panel is open, and once on mount so the icon is truthful
      // about a block that happened before the user ever clicked it.
      React.useEffect(() => {
        refresh()
        const timer = window.setInterval(refresh, open ? 1500 : 6000)
        return () => window.clearInterval(timer)
      }, [open, refresh])

      const flash = (message) => {
        setToast(message)
        window.setTimeout(() => setToast((current) => (current === message ? '' : current)), 2600)
      }

      // `makeT` builds a fresh closure on every render, so `t` has a new identity
      // each time. Using it as a `useCallback` dependency made `loadPanel` unstable,
      // and the "fetch on first open" effect below depends on `loadPanel` — so every
      // poll tick (1.5s) spawned another in-flight panel request while the first one
      // was still loading. A ref keeps the latest translator without joining the
      // dependency list.
      const tRef = React.useRef(t)
      tRef.current = t

      const loadPanel = React.useCallback(() => {
        setLoading(true)
        callPanel('state', {}, target, sessionId).then((result) => {
          setLoading(false)
          if (result && result.ok) setPanel(result.data)
          else flash((result && result.error) || tRef.current('panel.offline'))
        })
      }, [target, sessionId])

      // Switching conversations switches projects. Dropping the cached panel makes
      // the next open re-read the rules and allowlists of the new workspace instead
      // of showing the previous project's config under the new project's name.
      //
      // `sessionId` belongs here too: two windows can sit on the same project, and
      // their gate state is separate even though `target` is identical.
      React.useEffect(() => {
        setPanel(null)
        setEditing(null)
        setHistory(null)
        setState(null)
      }, [target, sessionId])

      const loadHistory = React.useCallback(() => {
        setHistoryLoading(true)
        // `verify` makes the Host re-read each edited line from disk and mark the
        // entry `current` / `reverted` / `stale` / `gone`. Without it the tab shows
        // write-time snapshots that silently drift away from the files.
        callPanel('history', { limit: 50, verify: true }, target, sessionId).then((result) => {
          setHistoryLoading(false)
          if (result && result.ok) setHistory(result.data)
          else flash(`${tRef.current('history.loadFailed')}${(result && result.error) || ''}`)
        })
      }, [target, sessionId])

      // Panel data is fetched on first open and after every write; keeping it out
      // of the 1.5s poll avoids re-reading 24 rules and six config files while the
      // user is looking at a scan result that has not changed.
      React.useEffect(() => {
        if (open && !panel) loadPanel()
      }, [open, panel, loadPanel])

      // The history is read when its tab is opened, and refreshed while it stays
      // open: the trail is append-only, but each entry's *status* is a claim about
      // the file right now, so it goes stale the moment somebody edits the code by
      // hand or reverts via git. A 4s cadence only while the tab is visible keeps
      // the badges honest without polling a JSONL in the background.
      React.useEffect(() => {
        if (!open || tab !== 'history') return undefined
        loadHistory()
        const timer = setInterval(loadHistory, 4000)
        return () => clearInterval(timer)
      }, [open, tab, loadHistory])

      // Outside click and Escape close the panel; both listeners live only while
      // it is open so the closed button costs nothing.
      React.useEffect(() => {
        if (!open) return undefined
        const onPointer = (event) => {
          // The button and the card are two separate nodes; a click in either one
          // belongs to the panel. Checking only the button closed the card on its
          // own first mousedown — the panel looked like it could never be used twice.
          const node = event.target
          if (rootRef.current && rootRef.current.contains(node)) return
          if (cardRef.current && cardRef.current.contains(node)) return
          setOpen(false)
        }
        const onKey = (event) => {
          if (event.key === 'Escape') setOpen(false)
        }
        document.addEventListener('mousedown', onPointer, true)
        document.addEventListener('keydown', onKey, true)
        return () => {
          document.removeEventListener('mousedown', onPointer, true)
          document.removeEventListener('keydown', onKey, true)
        }
      }, [open])

      const phase = phaseOf(state)
      const label = t(`phase.${phase}`)

      const toggle = () => {
        const next = !(state ? state.armed !== false : true)
        setState((current) => ({ ...(current || {}), armed: next }))
        callHost('arm', { armed: next }, target, sessionId).then((result) => {
          if (result && result.ok && result.state) setState(result.state)
        })
      }

      const reset = () => {
        setState((current) => (current ? { ...current, alert: '', phase: 'idle' } : current))
        callHost('reset', {}, target, sessionId).then((result) => {
          if (result && result.ok && result.state) setState(result.state)
        })
      }

      const runScan = (options) => {
        setScanning(true)
        setTab('scan')
        callPanel('scan', options, target, sessionId).then((result) => {
          setScanning(false)
          if (result && result.ok) {
            setPanel((current) => ({ ...(current || {}), scan: result.data }))
            if (result.state) setState(result.state)
            const verdict = (result.data && result.data.verdict) || '?'
            const files = (result.data && result.data.summary && result.data.summary.scanned_files) || 0
            flash(`${t('scan.done')}${verdict}（${files} ${t('scan.files')}）`)
          } else {
            flash(`${t('scan.failed')}${(result && result.error) || ''}`)
          }
        })
      }

      /** Every write goes through one helper so the reload-after-save is uniform. */
      const save = (patch, doneLabel) => {
        callPanel('save', patch, target, sessionId).then((result) => {
          if (result && result.ok) {
            const warnings = (result.data && result.data.warnings) || []
            flash(warnings.length ? warnings.join('；') : doneLabel)
            loadPanel()
          } else {
            flash(`${t('save.failed')}${(result && result.error) || ''}`)
          }
        })
      }

      const exempt = (finding) => {
        callPanel('ignore', { rule_id: finding.rule_id, path: finding.file }, target, sessionId).then((result) => {
          if (result && result.ok) {
            flash(`${t('act.exempt')} ${finding.rule_id} → ${finding.file}`)
            loadPanel()
          } else {
            flash(`${t('save.failed')}${(result && result.error) || ''}`)
          }
        })
      }

      const askAi = (finding) => {
        callPanel('fix-prompt', {
          rule_id: finding.rule_id,
          path: finding.file,
          line: finding.line,
          message: finding.message,
          evidence: finding.evidence,
          suggestion: finding.suggestion,
        }, target, sessionId).then((result) => {
          if (result && result.ok && result.data) {
            setEditing({ mode: 'prompt', finding, prompt: result.data.prompt })
          } else {
            flash(`${t('save.failed')}${(result && result.error) || ''}`)
          }
        })
      }

      const reveal = (finding) => {
        callPanel('reveal', { file: finding.file, line: finding.line }, target, sessionId).then((result) => {
          if (result && result.ok) {
            flash(result.data.method === 'vscode' ? `已在编辑器打开 ${finding.file}:${finding.line}` : '已在文件管理器中定位')
          } else {
            flash((result && result.error) || '跳转失败')
          }
        })
      }

      const editLine = (finding) => {
        callPanel('line-read', { file: finding.file, line: finding.line, context: 3 }, target, sessionId).then((result) => {
          if (result && result.ok && result.data) {
            setEditing({ mode: 'edit', finding, line: result.data })
          } else {
            flash((result && result.error) || '读取失败')
          }
        })
      }

      const commitLine = () => {
        if (!editing || editing.mode !== 'edit') return
        callPanel('line-write', {
          file: editing.finding.file,
          line: editing.line.line,
          text: editing.text,
          // The rule id is what makes the history entry traceable: without it the
          // record says "line 12 changed" and nothing about why.
          rule_id: editing.finding.rule_id,
          source: 'card',
        }, target, sessionId).then((result) => {
          if (result && result.ok) {
            const left = (result.data && result.data.remaining) || []
            flash(left.length ? `已保存，该文件还剩 ${left.length} 条问题` : '已保存，该文件已无问题')
            setEditing(null)
            setHistory(null)
            runScan({ mode: 'full', include_tests: false })
          } else {
            flash(`${t('save.failed')}${(result && result.error) || ''}`)
          }
        })
      }

      const openCard = () => {
        const rect = rootRef.current?.getBoundingClientRect?.()
        if (rect) {
          setAnchor({
            right: Math.max(12, Math.round(window.innerWidth - rect.right)),
            bottom: Math.max(12, Math.round(window.innerHeight - rect.top + 8)),
          })
        }
        setOpen((value) => !value)
        refresh()
      }

      const tabs = [
        ['scan', t('tab.scan')],
        ['rules', t('tab.rules')],
        ['allow', t('tab.allow')],
        ['ignore', t('tab.ignore')],
        ['ai', t('tab.ai')],
        ['history', t('tab.history')],
      ]

      let body = null
      if (offline) body = h('div', { className: 'dsh-cq-empty' }, t('panel.offline'))
      else if (state && state.message === 'scanner-missing') {
        body = h('div', { className: 'dsh-cq-empty' }, t('panel.noScanner'))
      } else if (editing) {
        body = h(
          'div',
          null,
          h('div', { className: 'dsh-cq-rule', style: { marginBottom: 6 } },
            `${editing.finding.rule_id} · ${editing.finding.file}:${editing.finding.line}`),
          editing.mode === 'prompt'
            ? h('div', { className: 'dsh-cq-ev', style: { maxHeight: 260, overflow: 'auto' } }, editing.prompt)
            : h(
                'div',
                null,
                h('div', { className: 'dsh-cq-ev' },
                  (editing.line.before || []).map((l) => `${String(l.n).padStart(4)}  ${l.text}`).join('\n')),
                h('textarea', {
                  className: 'dsh-cq-area',
                  spellCheck: false,
                  value: editing.text === undefined ? editing.line.text : editing.text,
                  onChange: (e) => setEditing({ ...editing, text: e.target.value }),
                }),
                h('div', { className: 'dsh-cq-ev' },
                  (editing.line.after || []).map((l) => `${String(l.n).padStart(4)}  ${l.text}`).join('\n')),
              ),
          h(
            Row,
            { style: { marginTop: 8 } },
            h(Button, { onClick: () => setEditing(null) }, t('act.cancel')),
            h('div', { className: 'dsh-cq-spacer' }),
            editing.mode === 'prompt'
              ? h(
                  Button,
                  {
                    variant: 'primary',
                    onClick: () => {
                      const text = editing.prompt
                      const done = () => flash(t('act.copied'))
                      if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(text).then(done, () => flash('复制失败'))
                      } else {
                        flash('复制失败')
                      }
                    },
                  },
                  t('act.copy'),
                )
              : h(Button, { variant: 'primary', onClick: commitLine }, t('act.save')),
          ),
        )
      } else if (loading && !panel) body = h('div', { className: 'dsh-cq-empty' }, t('panel.loading'))
      else if (tab === 'scan') {
        body = h(ScanTab, { t, panel, onScan: runScan, scanning, onExempt: exempt, onPrompt: askAi, onReveal: reveal, onEditLine: editLine })
      } else if (tab === 'rules') {
        body = h(RulesTab, { t, panel, onSave: (patch) => save(patch, t('rules.save')) })
      } else if (tab === 'allow') {
        body = h(AllowTab, { t, panel, onSave: (patch) => save(patch, t('allow.saved')) })
      } else if (tab === 'ignore') {
        body = h(IgnoreTab, { t, panel, onSave: (patch) => save(patch, t('ignore.saved')) })
      } else if (tab === 'history') {
        body = h(HistoryTab, {
          t,
          entries: history ? history.entries : null,
          loading: historyLoading,
          onReload: loadHistory,
        })
      } else {
        body = h(AiTab, {
          t,
          panel,
          onSave: (patch) => save(patch, t('ai.saved')),
          onTest: (form) =>
            callPanel('llm-test', { llm: { ...form, api_key: form.api_key || undefined } }, target, sessionId).then((result) =>
              result && result.ok ? result.data : { ok: false, error: (result && result.error) || '' },
            ),
        })
      }

      const card = open
        ? h(
            'div',
            {
              ref: cardRef,
              className: 'dsh-cq-card',
              style: { right: anchor.right, bottom: anchor.bottom },
              role: 'dialog',
              'aria-label': t('panel.title'),
            },
            h(
              'div',
              { className: 'dsh-cq-head' },
              EYE,
              h(
                'div',
                null,
                h('div', { className: 'dsh-cq-title' }, t('panel.title')),
                h('div', { className: 'dsh-cq-sub' }, `${t('panel.subtitle')} · ${label}`),
                target ? h('div', { className: 'dsh-cq-target', title: target }, target) : null,
              ),
              h(
                'button',
                { type: 'button', className: 'dsh-cq-x', 'aria-label': t('panel.close'), onClick: () => setOpen(false) },
                '✕',
              ),
            ),
            h(
              'div',
              { className: 'dsh-cq-tabs' },
              tabs.map(([key, text]) =>
                h(
                  'button',
                  {
                    key,
                    type: 'button',
                    className: 'dsh-cq-tab',
                    'data-active': String(tab === key),
                    onClick: () => {
                      setTab(key)
                      setEditing(null)
                      if (!panel) loadPanel()
                    },
                  },
                  text,
                ),
              ),
            ),
            h('div', { className: 'dsh-cq-body' }, toast ? h('div', { className: 'dsh-cq-hint' }, toast) : null, body),
            h(
              'div',
              { className: 'dsh-cq-foot' },
              h('span', { className: 'dsh-cq-label' }, t('foot.switch')),
              h('button', {
                type: 'button',
                className: 'dsh-cq-switch',
                'data-on': String(state ? state.armed !== false : true),
                'aria-pressed': String(state ? state.armed !== false : true),
                'aria-label': t('foot.switch'),
                onClick: toggle,
              }),
              h(
                'select',
                {
                  className: 'dsh-cq-select',
                  value: String((state && state.blockOn) || 'critical'),
                  onChange: (event) => {
                    const next = event.target.value
                    setState((current) => ({ ...(current || {}), blockOn: next }))
                    callHost('configure', { blockOn: next }, target, sessionId).then((result) => {
                      if (result && result.ok && result.state) setState(result.state)
                    })
                  },
                },
                h('option', { value: 'critical' }, t('foot.critical')),
                h('option', { value: 'warning' }, t('foot.warning')),
              ),
              h('div', { className: 'dsh-cq-spacer' }),
              state && state.alert
                ? h(Button, { variant: 'tiny', onClick: reset }, t('foot.reset'))
                : null,
            ),
          )
        : null

      return h(
        React.Fragment,
        null,
        h(
          'button',
          {
            ref: rootRef,
            type: 'button',
            className: 'dsh-cq-btn',
            'data-phase': phase,
            title: `${t('button.title')} · ${label}`,
            'aria-label': `${t('button.title')} · ${label}`,
            'aria-expanded': String(open),
            onClick: openCard,
          },
          EYE,
          h('span', { className: 'dsh-cq-dot', 'aria-hidden': true }),
        ),
        card,
      )
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.effect(() => insertStyles(), 'dsh-code-quarantine: styles')

        const locale = typeof ctx.get === 'function' ? ctx.get('locale') : undefined
        if (locale && typeof locale.register === 'function') {
          const safeRegister = (lang, dict) => {
            try {
              return locale.register(NS, lang, dict)
            } catch {
              return null
            }
          }
          for (const [lang, dict] of Object.entries(DICTS)) {
            ctx.effect(() => safeRegister(lang, dict), `dsh-code-quarantine: locale ${lang}`)
          }
        }

        ctx.slots.inject('conversation.input.right', () =>
          ctx.slots.register(
            {
              name: 'conversation.input.right',
              id: 'code-quarantine',
              order: 30,
              label: () =>
                locale && typeof locale.bind === 'function' ? locale.bind(NS)('button.title') : 'Code Quarantine',
              locale: NS,
            },
            QuarantineButton,
          ),
        )
      },
    }
  },
})
