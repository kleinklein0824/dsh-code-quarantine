# Changelog

遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号用 SemVer。

## [1.2.0] - 2026-10-24

第二版正式发布。本次更新将写入闸门从“点击后检查”推进为持续监测，补齐会话级
自动审计和安装级总开关，并修复 AI 配置、扫描状态、未保存表单与异常源码处理中
的一批实际问题。

### 新增

- **实时监测（无需点「开始扫描」）**：卡片新增首个标签页「实时监测」，Host 在
  `tools/pre-execute` 每拦一次写入就追加一条记录（文件、判定、规则、消息），
  通过 `liveRev` 计数推给卡片，卡片按该计数拉一次 `live-log`。监测从会话第一次
  工具调用就开始了 —— 工作区由 `session.header.cwd` 学到，**不依赖卡片是否被
  打开**，也不依赖任何按钮。状态帧只带 `liveRev / liveChecked / liveHits`，条目
  走独立读取，避免每变色一次就广播整张表。
- **总开关**：卡片底部新增安装级「总开关」，持久化到
  `$DSH_HOME/dsh-code-quarantine.settings.json`。关闭后写入拦截与会话创建时的
  自动审计都停用，图标变灰；手动扫描与规则/白名单/豁免/AI 配置仍然可用，
  随时可以再打开。原「写入拦截」开关保留，仍按会话隔离，并在总开关关闭时禁用。
- **会话创建时自动审计**：总开关打开（默认）时，`session/created` 会对新会话的
  工作区异步跑一次全量审计，结果直接进入图标与扫描页。审计走与卡片相同的
  `Panel.scan`，完整命中表缓存在 Host，卡片按 `scanRev` 取一次，状态帧仍然只带
  计数。子 agent 会话（`parentSession` / `delegationDepth > 0`）不会重复扫描父会话
  的工作区；工作区是 home、盘根或 `$DSH_HOME` 时跳过自动审计，避免空白会话把
  整个用户目录扫一遍。
- **外部配置实时同步**：Host 每 2 秒比对 `.dsh-quarantine.yml` 与
  `.dsh-quarantine-ignore` 的 `mtime + size`，手改文件或浏览器面板保存后向打开的
  卡片推送 `configRev`，规则/白名单/豁免/AI 表单自动重读。此前 README 声称有此
  行为，但只有浏览器面板实现了；卡片要等自己的下一次保存才会刷新。

### 修复

- **「深度复核」在卡片里不可达**：`ScanTab` 有 `deep` 状态却从未渲染控件，
  `llm_deep` 永远是 false。现在「用 AI 复核」旁边有「深度复核」勾选框，未勾
  AI 时禁用。
- **AI 状态说反了**：配置里 `enabled: false` 时，卡片与浏览器面板都显示
  「未配置完整」，让人去找并不缺的字段。现在明确显示「已关闭」；扫描笔记也
  区分「已关闭 / 端点无效 / 缺少某字段」。
- **「测试连接」在关闭状态下无法使用**：`llm_test` 把 `enabled` 也算进 `ready`，
  未勾启用时只回一句「缺少 」并附空字段名。测试连接现在只验证端点可达性，与
  「扫描是否使用它」解耦。
- **扫描的 AI 信任告警没有出口**：项目配置里的端点被信任门禁拒绝时，警告只留在
  JSON 响应里。卡片扫描页与浏览器面板现在把它显示在结果旁/提示里。
- **保存失败会丢掉未保存输入**：卡片的规则/白名单/豁免/AI 表单在点击保存时
  无论成功失败都清掉本地副本，保存失败后用户得凭记忆重做。现在只有写入成功才
  清空；AI 表单也不再永久停留在点击时的值，外部改动仍能刷新。
- **规则/白名单保存后扫描结果消失**：`loadPanel()` 用 bridge 的配置快照替换整个
  `panel` 对象，而快照没有 `scan` 键，于是一次配置刷新就把已加载的命中表打回
  「还没有扫描结果」。现在合并时保留 `scan`。
- **浏览器面板后台刷新会清掉未保存输入**：白名单、豁免、AI 表单没有脏检查，
  另一块面板保存一次就把用户打了一半的内容覆盖。现在只要这些表单有输入就跳过
  自动重载并提示；「用 AI 复核」是扫描选项，也不再被每次刷新重置。
- **干净项目被说成「没有符合条件的结果」**：扫描完成、零命中的表格原先一律显示
  过滤空态，读起来像"发现了但被筛掉了"。现在区分两种空：零命中显示「未发现问题」，
  只有确实被过滤条件筛掉时才说「没有符合条件的结果」。
- **首个拦截事件可能延迟 20 秒才推送**：SSE 连接发完首帧后、正式进入等待前到达
  的事件会丢掉一次条件变量通知。现在先快照 `seq / history / config` 再用谓词等待，
  已变化的状态不会被漏掉。
- **一个病态文件会拖垮整次审计**：`ast.parse` 是递归构造语法树，遇到单个超长
  表达式（如几千个 `+` 连写的生成文件）会抛 `RecursionError`，而
  `lexer.Source._scan_python` 只捕获 `SyntaxError`，异常一路冒到 `qcore.scan`，
  整个项目的审计直接中断。现在把 `RecursionError` 与 `SyntaxError` 同等对待：
  该文件标记 `parse_error`、`tree = None`，词法规则照常生效，只有依赖 AST 的
  规则对这个文件静默，项目其余文件不受影响。

### 测试

- `test-state.mjs` 92 → 128 项（总开关、持久化、自动审计、子 agent 跳过、
  外部配置推送）；`test-client.mjs` 36 → 56 项（总开关渲染、关闭后图标变灰、
  禁用会话开关、点击不误触、干净项目空态、扫描页可达性）；Python 单测 202 → 206
  项（另一块界面写入历史时浏览器历史页随文件变化收到推送、病态嵌套表达式不再让
  词法器抛 `RecursionError`）。
- Python 3.9/3.10 的解析器可以处理更长的表达式链，回归测试不再假定一定会抛
  `RecursionError`；新增显式模拟，锁定异常出现时的词法降级路径。
- 修正 `Panel._record_fix()` 的一个真实缺陷：`history.append()` 用返回值表示
  写失败，原代码不看返回值照样涨 `_history_rev`，页面会重读一次却仍看到旧内容。
- 新增真机验证：用真实 `@deepseek-ai/dsh-session` 创建会话，确认
  `session/created` 自动审计生效；总开关关闭时不扫描。

## [1.1.0] - 2026-10-22

以 `idea.md` 为验收基准做了一轮逐条核对（`tests/idea_matrix.py`，83 条断言），
补齐 9 处「方案里写了但产品没真正做到」的缺口，并治理了真实库上的误报。

### 新增

- **全部界面改为服务端推送，不再轮询**：面板与卡片各开一条 SSE 长连接
  （`GET /api/events/stream`、`GET /dsh-code-quarantine/events`），状态一变由服务端
  主动推一帧。用轮询时，一次落在 tick 之后的拦截要等满一个周期才显示，而这段空窗
  是看不见的——图标只是显得平静。卡片侧还多一道会话守卫：Host 已按会话路由，但
  「一个窗口的 BLOCK 涂红另一个窗口的图标」这个失败既静默又昂贵，用户会去错的
  项目里找问题。
- **DeepSeek-Harness 写入闸门插件** `dsh-plugin/`：DSH 没有 Claude Code 式的
  PreToolUse hook，真正的接缝是 `@deepseek-ai/dsh-tools` 的 `tools/pre-execute`
  waterfall。插件在其中拦截 5 个写入工具（`write` / `edit` / `ops_write_file` /
  `ops_edit_file` / `ops_replace`）与 3 个 shell 工具（`bash` / `ops_bash` / `pwsh`），
  命中 CRITICAL 时返回 `deny` 并把 evidence 与修复建议交给模型。
- **输入框里的「代码检疫」图标**（`dsh-plugin/client.js`）：一个纯图标的按钮，
  注册在 `conversation.input.right` 槽位，颜色随真实状态切换——检测中黄色脉冲、
  无问题绿色、有预警黄色、被拦截红色、已停用灰色。点开的卡片**与本地控制面板
  同构**，六个标签页：扫描结果（筛选 / 搜索 / 行内跳转·编辑·交给 AI·豁免）、
  规则开关（24 条逐条调级别与启停）、白名单（四类域名与 registry）、豁免清单、
  AI 复核（8 个字段 + 测试连接）、修复历史（每次改动的改前改后、对应规则、
  备份路径、改完还剩几条）。卡片通过 `/dsh-code-quarantine/rpc` 与 Host
  半部通信。
- **按会话隔离的闸门状态**（`dsh-plugin/index.js`）：状态机从「一个进程一份」改成
  「一个会话一份」。此前两个窗口开两个项目时，在 A 窗口关掉拦截会静默关掉 B 窗口，
  A 窗口拦下的 CRITICAL 会把 B 窗口的图标也涂红——一个按工作区生效的安全闸门变成了
  全局静音键。现在 `sessionId` 随每个 RPC 请求发出，Host 用它索引独立状态；拦截侧的
  归属取自 `tools/pre-execute` 的 `exec.agent.session.id`。拦截级别也按会话，扫描器的
  环境变量改为每次调用现拼（`envFor(runtime)`），不再共用一个启动时烘好的 `env`。
  拿不到会话时落到共享的 `''` 作用域：降级，但不误拦。
- **修复历史** `scripts/qcore/history.py`：每次「保存这一行」追加一行 JSON 到
  `.dsh-quarantine-history.jsonl`，带改前改后、`rule_id`、`source`、备份路径与
  改后剩余条数。用 JSON Lines 而不是 JSON 数组：追加是 O(1)，单行写坏最多丢最后
  一行，数组方案崩溃会毁掉全部记录。读取时跳过坏行，坏行不影响其余记录。面板侧
  走 `GET /api/history`，卡片侧走 RPC `panel{op:'history'}`。没有它，改完一行只
  剩一句两秒后消失的 toast 和一个只存旧内容的 `.bak`——备份目录里躺着一堆文件，
  没人能说出哪个对应哪条规则、哪次改动是为了什么。
- **修复历史的状态核对**：读取时带 `verify=1`，`Panel._entry_status()` 逐条回读
  磁盘标出 `current` / `reverted` / `stale` / `gone`。历史是写入时的快照，而代码
  会继续变——用户 `git checkout` 撤回之后，一条「已修复」记录如果仍显示为已修复，
  就是一条看起来和刚写的一样可信的假消息。面板与卡片都渲染状态徽标，并把被撤回
  条目的 `+ after` 调淡；停在历史标签时每 4 秒重读一次（只在可见时，不在后台轮询）。
- **`scripts/panel_bridge.py`**：把 `panel_server.Panel` 暴露成 stdin/stdout 上的
  JSON 调用。卡片的每个读写都落到这同一个对象上——**不复制任何判定或写配置逻辑**，
  否则两份实现会慢慢分叉，出现「面板里关掉的规则，卡片里还在报」。
- 卡片把会话工作区当作扫描目标（从 `useSessions` 的 `sessionId` 行取 `cwd`），
  并在标题下显示该路径；Host 侧拒绝相对路径与不存在的目录（`TARGET_NOT_ABSOLUTE`
  / `TARGET_MISSING`），而不是回落到自己的 `process.cwd()`——Host 的 cwd 是 profile
  目录，静默回落会去审计 `~/.dsh/profiles/<name>` 并把六个无关文件报成 clean。
- **bundle 形态**：`package.json` 带 `dsh.bundle.patch` + `dsh.client` + `icon`，
  附 `locale/{en,zh}.json` 与 `cordis.patch.yml`，可经 `plugin_manager` 安装，
  也是上架插件市场的基本单元。
- 四层测试：`test-gate.mjs`（23 项）、`test-e2e.mjs`（7 项）、
  `test-loader.mjs`（7 项）、`test-state.mjs`（92 项，状态机与 RPC）、
  `test-client.mjs`（36 项，卡片交互，自建极简渲染器——harness 的 react/react-dom 在本机不可用）。
- **`scripts/hook_shell.py`**：`curl … | bash` 这类命令不经过任何文件写入，
  写侧 hook 看不见，需要独立的 shell 门。
- **`scripts/install_hooks.py`**：把三条 hook（写入闸 `hook_pre_write.py`、
  命令闸 `hook_shell.py`、落盘复查 `hook_post_write.py`）幂等合并进
  `~/.claude/settings.json` 或 `~/.workbuddy/settings.json`，支持 `--status` /
  `--dry-run` / `--uninstall`，写前备份，保留用户已有 hook。
- **规则 `SC111`**「`chmod +x` 后在邻近行立即执行同一文件」（CRITICAL）。
- **规则 `SC112`**「JS/TS 动态模块加载：`require(变量)`、`import(拼接串)`」（WARNING）。
- **`tests/idea_matrix.py`**：idea.md 逐条实测台账，83 条断言。
- **`tests/realworld_regression.py`**：8 个真实库 581 个 `.py` 的误报回归，
  锁定 `CRITICAL 0 / WARNING ≤ 42 / INFO ≤ 120`。
- **`docs/idea-status.md`**：idea.md 条目 → 状态对照表。

### 修复

- **保存一次配置就抹掉用户的豁免清单**：`Panel.save()` 用
  `payload.get("ignore") or []` 决定写什么，于是「这次保存没提豁免」和「豁免清空」
  变成同一件事——任何只保存规则或白名单的调用方都会把手写积累的
  `.dsh-quarantine-ignore` 清空，且没有任何提示。那份清单没有备份，抹掉之后下一次
  扫描立刻满屏告警，用户还不知道是自己刚才点了保存。改成只有载荷**明确带了**
  `ignore` 键才重写文件。
- **配置监视线程一启动就崩**：`_watch_configs()` 第一行写的是
  `self._config_stamps = dict(self._config_stamp())`，而 `_config_stamp()` 返回的是
  三元组 `(name, mtime_ns, size)` 序列，`dict()` 当场抛
  `ValueError: dictionary update sequence element #0 has length 3; 2 is required`，
  线程死在启动那一刻。于是「手改配置文件面板会自动刷新」从未生效过，页面永远显示
  打开时的旧配置。改成直接保存元组并做元组比较。
- **URL 正则把代码当成了地址**：`URL_RE` 的字符类里带着单引号，
  `new URL(request.url, 'http://localhost').searchParams.get('session')` 被整体匹配成
  `http://localhost').searchparams.get('session`，「主机名」变成了 JavaScript 源码，
  报出来的告警连地址都不是。去掉单引号（引号是字符串边界，不是 URL 的一部分），
  句子结尾的标点仍由 `_clean_url()` 收尾。
- **黑名单地址在配置文件里完全查不出来**：`ad.scan()` 对 `DATA_LANGS`（`.env` /
  yaml / json / toml / ini）整类早退，而中转站端点写在 dotfile 里的概率远高于写在
  `.py` 里——把 `OPENAI_BASE_URL` 换成中转站地址是查不出来的（实测 `VERDICT: SAFE`）。
  新增 `_scan_blocked_hosts()`，在早退**之前**扫一遍：黑名单主机名出现在任何文件
  类型里都报 CRITICAL，带 scheme 与裸主机名都认。规则自身的配置文件不参与（否则
  自己举报自己），`blocked_domains` 为空时零开销。
- **AI 复核看不见端点替换**：提示词原来只让模型复核已有命中 + 补找语义问题，
  完全没提 `base_url`；而且复核循环跳过没有规则命中的文件，端点替换恰恰不产生
  任何命中。两处一起改：提示词带上 `blocked_domains` 原文与官方端点清单，
  并要求检查 `base_url` / `OPENAI_BASE_URL` / `endpoint` / `api_base`；
  新增极窄预筛选 `ENDPOINT_ASSIGN_RE`，只有出现端点赋值的文件才破例送审。
- **十六进制载荷检测失效**：`payload.py` 的去重集合以 `(start, end)` 为键，而
  base64 与 hex 对同一段纯 hex 文本产出完全相同的 span，base64 先占位后 hex 被跳过。
  改为 `(start, end, kind)` 且仅在解码成功后写入。
- **`os.system` / `os.popen` 完全漏检**：SC101 的 Python 分支只认 `ast.Name`，
  而 `os.system` 是 `ast.Attribute`。新增 `python_attr_calls` 与 Attribute 分支。
- **`.env` 不在敏感路径清单**：补入 SC103 的 `sensitive_paths`，并把路径匹配从
  裸 `re.finditer` 改为词边界，避免 `.env` 命中 `os.environ`。
- **跨行密钥外发漏检**：SC103 的环境变量分支只看单行；改为 AST 函数作用域内
  跟踪赋值目标名，`tok = os.environ[...]` 换行后再用也能报。
- **`--since` 错 ref 静默假绿**：`git diff` 失败被 `or []` 吞掉，输出 `SAFE` 且退出码 0。
  现在抛 `GitError` → `VERDICT: ERROR` → **退出码 3**（在 `--fail-on` 判定之前返回，
  避免被 `--fail-on none` 掩盖）。
- **AD002 注释区级别与文档不符**：`comment_severity` 由 `info` 改回 `warning`，
  对齐 idea.md 锚点 2 与 `SKILL.md`。
- **`wget -O- … | sh` 检测不到**：SC102 的 wget 正则要求 `-O` 后必须有空白，
  真实写法是 `-O-` / `-qO-` 连写。改为覆盖 `--output-document=`、`-O-`、`-O -`、`-qO-`。
- **`.npmrc` 等点文件依赖清单被整体跳过**：`lexer.detect_language('.npmrc')` 返回
  `unknown`，文件在 `scan.py` 就被跳过，SC109 在真实项目上从未生效。补 `FILENAME_LANG`
  条目 + 统一 `REGISTRY_FILES` 分派，并支持 `index-url` / `extra-index-url` /
  `npmRegistryServer` / `@scope:registry`。
- **AD004 精度**：裸词 `telegram` 会命中 `"telegram_oauth": False` 这类配置键；
  docstring 里的示例地址 `dp@x-force.example.com` 被当成硬编码联系方式。
  加标识符边界判断与占位域名过滤，并把邮箱级别从硬编码 INFO 提升为 WARNING
  （idea.md 锚点 4 要求 WARNING）。
- **插件拦截提示重复**：shell hook 已自带补救建议，插件又追加一遍。改为按
  「输出里是否已含补救措辞」判重。
- **规则加载失败仍然输出 SAFE**：`Config._load_rules()` 对缺失/损坏的规则文件只记
  一条 warning 就继续跑，剩下的规则照常工作，于是产出一份格式完整、合法的
  `VERDICT: SAFE`——CI 绿了，闸门是空的。现在 `rules_missing` 非空即判
  `VERDICT: ERROR` + 退出码 **3**；hook 侧明确打印「检查未完成，本次放行」而不是沉默。
- **面板保存抹掉手写配置**：表单只渲染它认识的字段，保存却是整块覆盖。
  点一下「保存规则」会抹掉用户手写的 `api_key`，并把 `api_key_env` 重置成硬编码默认值、
  `timeout` / `max_calls` 整段消失，端点随即失效且没有任何提示。
  改为按字段合并（`_merge_llm_block`），并补齐 `timeout` / `max_calls` 输入框。
- **非 ASCII token 打断连接**：`secrets.compare_digest` 对含非 ASCII 的 `str` 直接抛
  `TypeError`，一个 `?t=中文` 的探测请求就能让连接断在半路（curl 52 / 空响应），
  服务端看不到任何异常。改为先编码成字节再比较。
- **4xx 日志泄露 token**：请求行里带着 `?t=<token>`，原样写进日志等于把凭据
  落进终端历史与日志文件。现在按 `t=` / `X-Panel-Token` 脱敏。
- **并发「一键修复」丢更新**：两个并发请求都基于同一份旧内容算出新内容，
  后写的覆盖先写的；Windows 上两个 `os.replace` 抢同一目标还会抛
  `PermissionError` 变成 500。改为整个「读-改-写」串行。
- **备份秒级撞名**：同一秒内连点两次，第二次备份直接覆盖第一次，还原点少一个。
  改为撞名自动加序号。
- **Anthropic base 带 `/v1` 拼成 `/v1/v1/messages`**：`https://api.anthropic.com/v1`
  这种（与 OpenAI 习惯一致的）写法会拼错。改为按后缀判断。
- **模型能凭空造一条 CRITICAL**：`missed` 是模型的自由文本结论，没有证据链支撑。
  被投毒的模型（或塞进代码里的诱导提示词）可以让任意文件写不进去、让 CI 变红——
  把检测工具本身变成拒绝服务入口。AI001 现在最高只到 WARNING。
- **AI 缓存 key 不含模型**：换模型后仍复用旧模型的裁决，报告却写着新模型的名字。
  key 里加入 `provider|model`。
- **七个入口没强制 UTF-8**：`install_shortcut.py` / `install_hooks.py` /
  `make_icon.py` / `panel_server.py`，以及 `tests/brutal_suite.py` /
  `tests/idea_matrix.py` / `tests/realworld_regression.py`，都按控制台 ANSI
  代码页（中文 Windows 是 GBK）输出。中文提示让按 UTF-8 读管道的调用方
  `UnicodeDecodeError`，读线程崩溃后 `proc.stdout` 变成 `None`——
  `test_shortcut_script_dry_run` 一直是这么挂的，过去只能靠 `PYTHONUTF8=1` 绕过。
  七处统一加 `reconfigure(encoding="utf-8")`，现在**不设任何环境变量**也能
  182/182 全绿、100/100 通过、83/83 PASS。
- **装成包之后闸门静默失效**：`resolveSkillRoot()` 只试 `resolve(HERE, '..')`，
  源码 checkout 下正好是仓库根，装进 `node_modules/dsh-code-quarantine/` 后却是
  `node_modules/`——找不到 `scripts/`，`apply()` 在「no scanner found」处提前返回。
  表现是测试全绿、真机上一个 CRITICAL 都拦不住。改为按候选根逐个探测，
  并同时认 `~/.dsh/skills`、`~/.claude/skills`、`~/.workbuddy/skills` 等安装位。
  显式配置的 `skillRoot` 写错时不再回退到别的安装——那会悄悄换掉规则集。
- **缺扫描器时留下一个死按钮**：原来直接 `return`，Client 半部照旧渲染图标，
  但背后每个请求都 404。现在路由始终注册，状态里带 `message: "scanner-missing"`，
  审计返回 `NO_SCANNER`，界面能说清为什么不能用。
- **红色警告活不过几秒**：`phase` 是瞬时值，拦截一次之后再写一个无害文件就被
  覆盖成 CLEAN，图标变绿，而被拦下的内容还在用户剪贴板里。新增粘性 `alert`
  （只升不降），只有「清除提示」或一次干净的全量审计能降下来；计数也跟着粘住，
  避免出现「红图标 + C 0」的自相矛盾。
- **全量审计后计数不刷新**：`runScan` 返回的是扁平字段，代码却展开
  `{...result.counts}`（`undefined`），审计完仍显示上一次事故的数字。
- **包名形式的 entry 热更新不生效**：profile patch 里写 `name: 'dsh-code-quarantine'`
  时，运行中的进程会命中 ESM 模块缓存，改代码后 `apply()` 不会重新执行。
  改用 `file:///…` 绝对 URL，每次 patch 变更都重新 import。
- **卡片点开后再也点不动**：卡片是按钮的兄弟节点（要 `position: fixed` 定位到
  视口，不能嵌进 composer 的 inline 行），而「点外部就关闭」的判定只查了按钮
  `rootRef`。于是卡片里任何一次 `mousedown`（切标签、点下拉、点输入框）都被
  当成外部点击，面板当场关掉——表现就是「打开后无法二次操作」。现在按钮和卡片
  两个节点都算「面板内」。顺带修了 `loadPanel` 的依赖：`makeT` 每次渲染都造新
  闭包，把 `t` 放进依赖会让它在每轮 1.5s 轮询时都重建并发一次在途请求。
- **HTML 页面完全测不到**（用 `demo/d1api-home.html` 复刻真实中转站首页时发现）：
  `lexer._scan_markup` 只把 `<!-- -->` 标成注释，属性值与文本节点既不是
  `comment` 也不是 `string`。广告规则靠 `_aux_text_by_line` 收 comment/docstring/
  string 三种 span 建逐行文本缓存，HTML 的 span 集为空 → AD001 的话术窗口永远
  扫不到东西；AD002 的「代码字符串外链」分支也只在 `region == "string"` 进入，
  同时沉默。整页写着「推荐访问」「购买套餐 / 充值：发卡网购买链接」和一串外链，
  判定是 `SAFE 0/0/0`。现在属性值、文本节点都标成 `string`，`<script>` /
  `<style>` / `<textarea>` 的块体保持 `code` 交给 JS 与 shell 规则；
  `_skip_tag` 跳过引号内的 `>`（`?a=1>2` 不会把标签切一半）；闭合标签不再走
  「跳过块体」分支（首版漏判导致 `</style>` 把整篇文档吞成一段 raw text，
  span 数从 168 掉到 11）。
- **AR004 承诺了「且未见对应测试更新」却从不检查**：消息里写着这句话，实现只比对签名——于是每次有意的重构都会亮，而用户去查发现测试明明更新了。现在增量模式用 `changed` 集算 `tests_changed`：测试文件也在变更集里就不报；全量扫描没有变更集，`tests_changed` 保持 `None`，消息不再声称测试未更新（全量扫描断言「谁没改」属于推断，正是 idea.md 禁止的）。
- **裸域名把属性名当域名**：`BARE_DOMAIN_RE` 的 TLD 表含 `top` / `cc` / `me`，
  自扫描时 `Math.round(window.innerHeight - rect.top + 8)` 被判成「外部域名命中
  风险特征: rect.top」——一条把正常布局计算报成推广域名的告警。裸域名本来就只
  是 AD001 的共现锚点（`访问 relay-hub.com 领取额度` 这种写法不带 scheme），
  锚点应当只来自人类写的文本，所以限制在 comment / docstring / string 区。
- **AD005 没豁免测试路径**：AD001/AD002/AD004 都有 `not is_test`（夹具里必须
  存在恶意样本，否则测不了），AD005 漏了同一条。后果是给规则写回归用例时，
  闸门把「测试夹具里必须存在的恶意样本」判成 CRITICAL 并拒绝写入——检测工具
  被自己的夹具锁死。补 `and not is_test`，与另外三条对齐。
- **面板 RPC 的 target 守卫只查信封**：`panel` 的目录来自嵌套的 `args`，而
  守卫只读顶层 `args.target`。把同一个坏路径往下一层放就能绕过——守卫成了装饰。
  现在两层都校验，非绝对路径与不存在的目录都返回 400。

### 变更

- **误报治理三条机制**：
  1. 项目自述域名豁免——从 `pyproject.toml` / `package.json` / `PKG-INFO` 的
     结构化字段（`homepage`、`Project-URL`）读官方站点，不参与注入判定。
     刻意不读 README（满是第三方徽章，且易被投毒者改写）。
  2. 引用式链接降级——`[text](url)`、`[ref]: url`、RST `` `text <url>`_ ``、
     `>>>` doctest、`See/Ref/Based on …` 判为引用，降 INFO 而非 WARNING。
  3. 占位主机名跳过——`foo.com`、`host`、`example.*`、`xn--…`、含 `_` 的非法域名。
- **AD001 英文词表重整**：`recommended` / `visit` / `sign up` 这类单词会把
  `Refer to … for the recommended approach.` 这种官方文档句判成推广，删掉；
  英文改为匹配明确营销句式（`Get your … key`、`Powered by`、`Register at`、
  `Cheapest relay`、`Use this mirror instead` …），中文保留低歧义词。
- **测试**：79 → 202 个单元用例（新增 56 个缺口回归 + 4 个 shell/安装闸用例
  + 11 个面板读写、信任门禁与 AI 边界用例 + 13 个 markup 词法与 HTML 检测用例
  + 3 个裸域名精度用例 + 4 个 SSE 推送与配置监听用例）。`tests/brutal_suite.py`
  仍 100/100。
- **`tests/functional_sweep.py`**：44 项端到端功能检测。单测证明函数算得对，它证明
  **用户能碰到的入口真的还能用**——十组检查串起 `--list-rules` / `--explain` /
  四种报告格式 / 五种退出码 / 五种扫描模式 / `--since` 错 ref / 签名基线 /
  豁免文件 / 三个 hook / `panel_bridge.py` / DSH 插件 RPC。真机那组在 GUI 没跑时
  打印 `[SKIP]` 而不是失败。首次运行就抓到三个真问题（`--write-baseline` 的参数
  语义、RPC 嵌套 target 绕过守卫、以及它自己写不出来）。
- **`demo/d1api-home.html` + `docs/d1api-replica-check.md`**：真实中转站首页的逐字
  复刻（299 字符可见文字）与检测记录。它既是「HTML 能不能测」的回归夹具，也是
  一份可复现的检测报告：修复后 8 条 WARNING 逐条核对无一条误报。
- **CI**：新增 `idea_matrix.py`、`realworld`（真装 8 个库跑误报回归）、
  `dsh-plugin`（Node 22 跑四层插件测试）、`functional_sweep.py --quick`
  （每个 Python 版本都跑一遍入口层）四个检查。
- `dsh-plugin/test-e2e.mjs` / `test-loader.mjs` 在找不到 harness 包时跳过并说明
  （CI runner 与只读仓库的人没有 DSH profile 是正常状态），而不是崩溃。

### 设计取舍（新增）

- 时间炸弹这类**纯逻辑条件**抓不到：只认结构锚点，不做语义证明。已在能力边界写明。
- 引用式链接降 INFO 而非丢弃：真推广会先被 AD001（话术 + 外链共现）命中并保持 WARNING。
  需要严格模式的项目可把 `AD002.data.citation_severity` 改回 `warning`。

## [1.0.0] - 2026-10-21

首个可发布版本。

### 新增

- **三层规则引擎**，22 条规则：
  - 广告注入 `AD001`–`AD005`
  - 供应链投毒 `SC101`–`SC110`
  - 架构偏离 `AR001`–`AR006`（仅 Python AST）
  - AI 复核补漏 `AI001`
- **双模式**：`hook_pre_write.py`（写入前阻塞）/ `hook_post_write.py`（落盘后回灌），
  以及 `quarantine.py --full/--incremental/--since/--files/--stdin`。
- **AI 复核层**（`qcore/llm.py`）：OpenAI 兼容与 Anthropic 两种协议，
  自动识别当前对话模型名，支持自定义端点与密钥；无密钥时完全跳过并如实标注。
- **控制面板**（`panel_server.py` + 单文件前端）：扫描、规则开关、白名单、豁免、AI 配置；
  每条命中支持 **跳转 / 行内编辑 / 交给 AI / 豁免**。
- **事件推送**：hook 拦截后推给运行中的面板，顶部横幅即时显示。
- **状态栏**：`statusline.py` 输出 `👁 BLOCK · 8C/16W · 13 文件 · 2m 前`。
- **品牌资源**：荷鲁斯之眼 SVG + 多尺寸 ICO，桌面/开始菜单快捷方式。
- **报告格式**：`text` / `json` / `md` / `sarif`，退出码 `0/1/2` 供 CI gate。
- **测试**：79 个单元用例（含 18 个安全用例）+ 100 个地狱式功能用例（`tests/brutal_suite.py`）。

### 安全

- 面板：符号链接逃逸拒绝、路径归属校验（realpath + normcase）、请求体 4MB / 单文件 5MB 上限、
  全部写入改为原子写、`nosniff` / `no-referrer` / `X-Frame-Options` / CSP 响应头、前端字段全量转义。
- AI：项目配置里的端点不再自动启用（需 `--llm` 或 `DSH_QUARANTINE_LLM_TRUST_PROJECT=1`），
  只接受 http/https；模型不能推翻 CRITICAL，低置信度推翻被忽略；提示注入防护。
- hook：内容上限 2MB；hook 自身异常时放行并说明，避免锁死工作流。

### 设计取舍

- 精度优先（"宁可漏报，不可误报"）：URL 必须带结构锚点才判注入；
  `exec/eval` 用轻量污点判断，避免把 REPL、调试器、模板编译当成后门。
- 只有 Python 有真正的 AST 判定，其他语言明确降级为词法层并在报告中声明能力缺口。
- 面板不复制任何判定逻辑，扫描统一走 `qcore.scan`，保证与 CLI 结论一致。
