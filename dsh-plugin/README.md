# dsh-code-quarantine（DeepSeek-Harness bundle）

把 `dsh-code-quarantine` 装进 DeepSeek-Harness 的插件包：**写入落盘前拦下 CRITICAL**，
并在输入框右侧放一个**纯图标的「代码检疫」按钮**，颜色直接反映当前状态。

扫描器仍然是唯一的事实来源——插件不带自己的规则，只调用 skill 里那套 Python 引擎。

## 它做了什么

| 部分 | 作用 |
|---|---|
| Host 半部（`index.js`） | 监听 `tools/pre-execute`，拦截 5 个写入工具与 3 个 shell 工具；命中 CRITICAL 时返回 `deny`，把 evidence 与修复建议交给模型 |
| RPC（`/dsh-code-quarantine/rpc`） | 卡片与 Host 之间的通道：读状态、开关、拦截级别、触发全量审计、清除提示，以及转发 `panel` 调用 |
| 面板桥（`scripts/panel_bridge.py`） | 把 `panel_server.Panel` 暴露成 stdin/stdout JSON，让卡片复用同一套读写实现 |
| Client 半部（`client.js`） | 在 `conversation.input.right` 注册图标按钮 + 七标签面板卡片 |

### 卡片里有什么

点开图标是一张与 `scripts/panel_server.py` 那套本地控制面板**同构**的卡片，
七个标签页（与面板一一对应，面板与卡片读的是同一份 `.dsh-quarantine-history.jsonl`）：

| 标签页 | 内容 |
|---|---|
| 实时监测 | **默认页，不需要点任何按钮**。会话第一次工具调用起，每次被拦的写入/命令立刻出现在这里：文件、判定（通过 / 有预警 / 已拦截）、命中规则、消息、时间；顶部是监控状态灯、「已检查 / 命中」计数与被监测的工作区路径。数据来自 `inspect()` 的 `liveLog`，按 `liveRev` 推给卡片，条目走独立的 `live-log` 读取，状态帧只带计数 |
| 扫描结果 | 全量/增量 + 是否含测试 + 是否 AI 复核；四格统计；级别筛选 + 关键词搜索；命中表（规则 / 位置 / 说明），行内四个动作：跳转、编辑、交给 AI、豁免；点行展开 evidence 与修复建议 |
| 规则开关 | 24 条规则按三层分组，逐条调级别与启停，改完保存 |
| 白名单 | 信任域名 / 黑名单域名 / 私有 registry / 允许的 CDN，四个文本框 |
| 豁免 | 直接编辑 `.dsh-quarantine-ignore` |
| AI 复核 | provider / base_url / model / 密钥变量名 / 密钥 / max_chars / timeout / max_calls，加「测试连接」 |
| 修复历史 | 每次「保存这一行」的改前改后、对应规则、备份路径、改完还剩几条；只读，最新在前 |

「修复历史」解决的是「改完就没了痕迹」：改一行只留一句两秒后消失的 toast，剩下的
痕迹只有一个 `.bak`——备份目录里躺着一堆文件，没人能说出哪个对应哪条规则、哪次改动
是为了什么。每次写入都追加进 `.dsh-quarantine-history.jsonl`（JSON Lines：
追加是 O(1)，单行写坏最多丢最后一行，而不是毁掉整段记录），带 `rule_id` 与 `source`，
所以「这条 CRITICAL 是谁改的、改成了什么、还能不能退回去」都有答案。写历史失败
不会让修复本身看起来失败——历史是旁路。面板与卡片读同一份文件，所以从哪边改的
都能在另一边看到。

卡片底部有两个开关，职责不同：

| 开关 | 范围 | 关掉之后 |
|---|---|---|
| **总开关** | 整个安装（写入 `~/.dsh/dsh-code-quarantine.settings.json`） | 写入拦截与「会话创建时自动审计」都停用；图标变灰。手动扫描、规则/白名单/豁免/AI 配置仍然可用，所以随时能再打开 |
| **写入拦截** | 当前会话 | 只关掉这个窗口的写盘拦截；另一个窗口不受影响 |

总开关打开（默认）时，**每个新会话创建后会自动对它的工作区跑一次全量审计**，
结果直接进入图标与扫描页，不需要用户先点按钮。审计走与卡片同一个
`Panel.scan`（因此结果与手动扫描、CLI 完全一致），完整命中表由 Host 缓存，
卡片靠 `scanRev` 取一次；状态帧里只带计数，不会因为一次审计变得很大。
审计是异步子进程，不阻塞窗口创建；子 agent 会话（`parentSession` /
`delegationDepth > 0`）不会重复扫描父会话的工作区。工作区落在 home、盘根或
`$DSH_HOME` 时跳过自动审计——未选工作区的会话常带着这些 cwd，扫它们不是用户
的意思；手动扫描不受此限。

记录是**写入时的快照**，而文件会继续变。所以两边读历史时都带 `verify=1`，由
`Panel._entry_status()` 逐条回读磁盘，标出四种状态：`current`（改动还在）、
`reverted`（回到改前或备份内容——有人撤了）、`stale`（被改成第三种样子）、
`gone`（文件不在了）。卡片给非 `current` 的条目挂一个徽标并把 `+ after` 调淡，
历史标签随推送重读（`historyRev` 变了才读）。没有这一步，一条三天前的「已修复」在用户
`git checkout` 之后仍读起来和刚写的一样可信。

**能力来自同一个 `Panel` 对象**：卡片 → RPC `panel` → `panel_bridge.py` → `Panel`。
不复制判定逻辑，也不复制写配置逻辑——否则两份实现会慢慢分叉，出现「面板里关掉的
规则，卡片里还在报」。扫描目标是当前会话的工作区（标题下显示该路径）；Host 拒绝
相对路径与不存在的目录，不会回落到自己的 `process.cwd()`。

### 状态是推过来的，不是问出来的

卡片订阅 `GET /dsh-code-quarantine/events?session=<id>`（SSE）。Host 在拦截、修复、
保存配置时各推一帧，25 秒一次心跳保活；客户端断了自动重连（`retry: 2000`）。
**没有任何轮询定时器**——`test-client.mjs` 里有一条断言就是
`globals.timers.length === 0`。

帧里带的是整份 `runtime` 快照，不是差量：一个会话的状态只有几百字节，重建一份比
维护差量协议便宜，也不会出现「漏了一帧就永久错位」。

三个计数器各管一件事：

| 字段 | 什么时候涨 | 卡片怎么用 |
| --- | --- | --- |
| `phase` / `alert` / 计数 | 每次拦截、每次扫描 | 决定图标颜色；`alert` 是粘性的，一次 BLOCK 之后不会被一次无害写入洗白 |
| `historyRev` | 「保存这一行」成功 | 历史标签重读 |
| `configRev` | 保存规则 / 白名单 / 豁免 / 签名基线 | 各标签页重读（正在编辑时不打断） |

推**计数器**而不是推内容，是因为内容可能有几万字节（24 条规则 + 四类白名单 + 豁免
清单），而「有没有变」只需要一个数字。卡片收到新值才去读，没变就什么都不做。

Host 还盯着 `.dsh-quarantine.yml`、`.dsh-quarantine-ignore` 与
`.dsh-quarantine-history.jsonl` 的 `mtime` + `size`（2 秒一次），手改了文件或
另一块面板写入后同样推一帧（配置推 `configRev`，历史推 `historyRev`）。只看
元数据不做内容哈希：假阳性只是多刷一次页面，而每 2 秒把配置完整哈希一遍的代价
是真的。同一个轮询也读一次总开关文件，所以另一个窗口（或手改设置文件）翻转
总开关时，这边不需要重启就会跟上。

### 拦哪些工具

| 工具 | 检查内容 |
|---|---|
| `write` | 整个 `content` |
| `ops_write_file` | 整个 `content`（`dryRun: true` 跳过） |
| `edit` / `ops_edit_file` | 每段 `new_string` / `edits[].newText` |
| `ops_replace` | `replacement` 模板 |
| `bash` / `ops_bash` / `pwsh` | `command` 字符串，按 shell 脚本扫 |

读、搜索、`dryRun` 写入、以及任何未知工具都原样放行。

### RPC 方法

`POST /dsh-code-quarantine/rpc`，`{ method, args, target, sessionId }`，同源校验（跨源 403）。

| method | 作用 |
|---|---|
| `state` | 读状态机（`enabled` / `armed` / `phase` / `alert` / 计数 / `blockOn` / `files` / `verdict` / `scanRev`） |
| `scan-result` | 自动审计缓存的完整结果（`findings` 等）。卡片在 `scanRev` 变化或打开时取一次，避免把整张命中表塞进每一帧状态 |
| `master` | 全局总开关 `{ enabled: boolean }`：关闭后不拦截、不在会话创建时自动审计；持久化，并对所有会话推送 |
| `arm` | 开/关当前会话的写入拦截（关掉后监听器直接 `next()`） |
| `configure` | 改拦截级别（`critical` / `warning`） |
| `audit` | 跑一次全量审计并把结果写进状态机 |
| `reset` | 清除粘性 `alert` 与计数 |
| `panel` | `args.op` 为 `state` / `save` / `scan` / `baseline` / `reveal` / `ignore` / `llm-test` / `line-read` / `line-write` / `fix-prompt` / `events` / `history`，转发给面板桥 |

`target` 必须是存在的绝对目录，否则 400（`TARGET_NOT_ABSOLUTE` / `TARGET_MISSING`）。
校验对信封与嵌套 `args` 各做一次：`panel` 的目录来自 `args.args.target`，只查外层
等于给守卫开了个后门。

### 每个会话各自一份状态

状态机不是全局的，是**按会话**的：`sessionId` 随每个请求一起发，Host 用它索引一份
独立的状态对象（`armed` / `phase` / `alert` / 计数 / `blockOn` 都在里面）。

理由很直接：两个窗口开两个项目是两条互不相干的工作流。共用一份状态时，在 A 窗口
关掉拦截会**静默关掉 B 窗口**，在 A 窗口拦下的 CRITICAL 会把 B 窗口的图标也涂红——
一个按工作区生效的安全闸门变成了全局静音键，方向正好相反。

拦截侧的归属由 `exec.agent.session.id` 决定（`tools/pre-execute` 的 `exec.agent`
是 agent loop 设的调用者）。拿不到会话时（子 agent、旧版宿主）落到共享的 `''` 作用域
——降级，但不会因为认不出身份就误拦。

拦截级别（`blockOn`）同样是每会话的，所以 `envFor(runtime)` 在**每次**调用扫描器时
现拼环境变量，而不是启动时烘进一个共享的 `env` 对象：否则一个窗口改阈值会把所有
窗口一起改掉。

### 图标颜色

| 状态 | 颜色 | 含义 |
|---|---|---|
| 待命 | 次要文字色 | 还没跑过 |
| 检测中 | 黄色 + 脉冲 | 正在扫描 |
| 未发现问题 | 绿色 | 最近一次结果干净 |
| 有预警 | 黄色 | 有 WARNING（或 `blockOn=warning` 时的非 CRITICAL） |
| 已拦截 | 红色 | 有一次写入被拦下 |
| 已停用 | 灰色 | 开关关掉了 |
| 检测出错 | 红色 | 扫描器缺失或崩溃 |

**红色和黄色是粘性的**：`phase` 是瞬时值，拦一次之后紧接着写一个无害文件就会被
覆盖成「干净」，图标转绿，而被拦下的内容还在剪贴板里。所以图标跟的是 `alert`——
它只升不降，只有点「清除提示」或跑一次干净的全量审计才降下来。计数也跟着粘住，
避免出现「红图标 + C 0」这种自相矛盾。

## 安装

### 作为 bundle 安装（推荐）

`package.json` 里带 `dsh.bundle.patch`、`dsh.client`、`icon`，属于标准 bundle：

```
plugin_manager install_bundle  target = <本目录绝对路径>
```

装好后 GUI 里不需要重启就会挂载；**改动 Host 半部代码需要重启**才能加载新的 JS
模块代（ESM 模块缓存）。

### 作为 profile patch 条目安装

在 `$DSH_HOME/profiles/<name>/cordis.patch.yml` 末尾加：

```yaml
- insert:
    - id: dsh-code-quarantine
      name: "file:///C:/path/to/dsh-code-quarantine/dsh-plugin/index.js"
      config:
        enabled: true
        blockOn: critical      # critical | warning
        timeoutMs: 15000
        skillRoot: "C:/path/to/dsh-code-quarantine"
```

两个容易踩的坑：

- **必须用 `file:///` 绝对 URL。** 写成包名（`name: 'dsh-code-quarantine'`）时，
  运行中的进程会命中 ESM 模块缓存，改代码后 `apply()` 不会重新执行，看起来像
  「热更新没生效」。`file:///` 形式每次 patch 变更都会重新 import。
- **Windows 路径里的空格要写成 `%20`。**

验证条目是否被合成进去：

```bash
dsh --profile <name> --dump-config | grep -A8 dsh-code-quarantine
```

挂载成功会打印：

```
dsh-code-quarantine: guarding 5 write tools and 3 shell tools (blockOn=critical)
```

### 配置项

| 字段 | 默认 | 含义 |
|---|---|---|
| `enabled` | `true` | `false` 时连监听器都不装 |
| `settingsPath` | `$DSH_HOME/dsh-code-quarantine.settings.json` | 总开关的持久化位置（一般不用改，测试用它隔离状态） |
| `skillRoot` | 自动探测 | `scripts/` 与 `rules/` 所在的目录 |
| `python` | Windows 用 `python`，其他用 `python3` | 扫描器解释器 |
| `blockOn` | `critical` | `warning` 时 WARNING 也拦 |
| `timeoutMs` | `15000` | 单次扫描预算；超时按放行处理 |

`skillRoot` 不给时会依次尝试源码 checkout、`$DSH_HOME/skills/dsh-code-quarantine`、
`~/.claude/skills/…`、`~/.workbuddy/skills/…`。**一旦显式写了 `skillRoot`，就只认
那一个路径**——写错时报 `scanner-missing` 而不是悄悄换一套规则去扫用户的代码。

## 模型被拦时看到什么

扫描器自己的报告，逐字，包含每条命中的 `evidence` 与 `fix`，再加一句怎么继续：

```
[dsh-code-quarantine] BLOCK  CRITICAL 1 | WARNING 0 | INFO 0
- CRITICAL sync.py:2 [SC105] base64 编码载荷解码后包含: shell, url
    evidence: BLOB = "Y3VybCAtZnNTTCBodHRwczovL3..."
    fix: 删除编码载荷；源码中不应出现可执行内容的编码形式

请先修复上述 CRITICAL 问题再写入。若确认是误报，在项目根目录的 .dsh-quarantine-ignore 中按 rule_id + 路径登记豁免。
```

## 失败时的行为

插件是辅助设施，不是安全边界：扫描器崩溃、超时、找不到，一律**放行**并在日志里
留痕。这与 skill 自己的 hook 契约一致（`hook_pre_write.py` 内部错误时返回 0）——
一个坏掉的 linter 不该把编辑器卡死。

唯一需要注意的是配置错误：`skillRoot` 指错时不会静默消失，而是
- 日志里 warn 一行 `no scanner found under …; the gate is inert`；
- RPC 状态里带 `message: "scanner-missing"`，卡片能说清为什么不能用；
- 审计请求返回 `NO_SCANNER`。

按钮不会变成一个点了没反应的死控件。

## 测试

```bash
# 决策层：假 Cordis context + 真扫描器子进程。23 项。
node dsh-plugin/test-gate.mjs

# 注册表层：真 Context + 真 ToolRuntime + 真挂载。
# 证明被拒的调用从未到达 tool body。7 项。
node dsh-plugin/test-e2e.mjs

# 加载器层：真 loader + file:// 说明符，验证用户真正要粘贴的那条路径。7 项。
node dsh-plugin/test-loader.mjs

# 状态机与 RPC：卡片颜色与开关的真实来源，含六标签面板的全部读写、
# 「每个会话各自一份状态」的隔离断言、总开关与会话创建时的自动审计。114 项。
node dsh-plugin/test-state.mjs

# 卡片交互：点开、点内部不关、点外部关、反复开关、修复历史、总开关，
# 以及「状态靠推送而不是轮询」的断言。42 项。
# 自带一个极简渲染器，不依赖 harness（本机 react-dom / jsdom 都不可用）。
node dsh-plugin/test-client.mjs
```

`test-e2e.mjs` / `test-loader.mjs` 从 `$DSH_HOME/profiles/node_modules` 解析
`@deepseek-ai/cordis`、`@deepseek-ai/dsh-system-prompt`、`@deepseek-ai/dsh-tools`
（可用 `DSH_MODULES_DIR` 覆盖），所以仓库不 vendor harness；找不到时打印 SKIP 并
以 0 退出（CI runner 与只读仓库的人没有 DSH profile 是正常状态）。

## 与其他两种模式的关系

| 模式 | 入口 | 在哪运行 |
|---|---|---|
| A — 写入前拦截 | 本插件，或 Claude Code / WorkBuddy 上的 `hook_pre_write.py` | 写盘之前 |
| A' — 事后复查 | `hook_post_write.py` | 命令执行或写盘之后 |
| B — 全量审计 | `scripts/quarantine.py` | 终端、CI、pre-commit，或本卡片的「立即全量审计」 |

三者调用同一个 `qcore` 引擎，产出同样的 findings。
