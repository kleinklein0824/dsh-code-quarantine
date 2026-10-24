---
name: dsh-code-quarantine
description: 检查 AI 生成或中转站返回的代码是否存在广告注入、推广 URL、供应链投毒特征与架构偏离。适用于「刚写完/刚拉下来的代码要过一遍质检」「怀疑中转站往输出里塞了推广内容」「依赖清单或安装脚本被动过手脚」「需要 CI 里卡一道输出层安全门」等场景。双模式：写入前增量拦截 + 任务结束后全量审计。
---

# dsh-code-quarantine

代码输出层质检：在「模型输出被写进项目」这一刻和「任务收尾」这一刻各设一道闸。
不替代通用 SAST，补的是 AI 输出链路的空白。

## 安装后怎么"按"它

| 入口 | 形态 | 说明 |
| --- | --- | --- |
| **斜杠** | 输入框里打 `/dsh-code-quarantine` | 宿主渲染的技能条目，显示的名字与描述来自本文件 frontmatter |
| **小窗** | 独立窗口（Chrome app 模式） | 标题栏与任务栏都是荷鲁斯之眼图标，可右键钉到任务栏 / 开始屏幕 |
| **状态栏** | 对话界面底部常驻一行 | `👁 BLOCK · 8C/16W · 13 文件 · 2m 前`，只读缓存不跑扫描 |
| **写入闸门** | DeepSeek-Harness 插件 / Claude Code hook | 见「自动触发」一节，命中 CRITICAL 时直接拒绝写入 |

**关于"输入框里的自定义按钮"**：`SKILL.md` 的 frontmatter 只认
`name / description / version / allowed-tools / license`，没有 `icon` 字段，也没有让 Skill
往输入框注入 UI 的扩展点——输入框里的按钮归宿主所有。所以"按键"按上面的四层落地：
斜杠入口在框内，小窗、状态栏与写入闸门在框外常驻。

图标资产：`assets/eye-of-horus.svg`（矢量，面板 favicon 与页头）与
`assets/eye-of-horus.ico`（16/24/32/48/64/128/256，快捷方式用），改图后跑
`python scripts/make_icon.py` 重新生成 ico。

## 核心原则（先立规矩）

**宁可漏报，不可误报。** 误报一次，团队就会把 Skill 关掉；漏报可以通过多轮增量补漏。
因此：

1. 每条命中必须带真实 `file:line` 与实际读取到的代码 `evidence`，**禁止基于推断报告问题**。
2. 判定必须结合语法结构（注释 / 字符串 / 代码区），不允许纯字符串匹配直接下结论。
3. 拿不到语法树时，明确降级为词法层检测，并在报告 `capabilities` 中声明能力缺口，**绝不用正则假装 AST**。
4. 不确定的一律降级为 `INFO`，而不是硬报 `CRITICAL`。

## 何时用

| 场景 | 用什么 |
| --- | --- |
| 每次 `Write` / `Edit` 之后想立刻拦 | 模式 A：DeepSeek-Harness 用 `dsh-plugin/`，Claude Code 用 `hook_pre_write.py`（阻塞）/ `hook_post_write.py`（回灌） |
| 每次 `Bash` 想拦 `curl \| bash` | `hook_shell.py`（hook 形态）或 `dsh-plugin/`（插件形态，含 `bash`/`ops_bash`/`pwsh`） |
| 任务收尾、PR 前、CI 里 | 模式 B：`quarantine.py --full` |
| 只想看本次改动 | `--incremental` / `--since <ref>` / `--files a.py b.py` |
| 手里只有一段代码片段 | `--stdin --path x.py` |
| 想可视化调规则 / 加白名单 / 点豁免 | 控制面板 `panel_server.py` |

## 执行指令（核心约束）

1. **先确认语言集合**，再决定用哪层规则。Python 走内置 `ast`；其余语言只有词法层，架构级检查直接跳过并在报告里说明。
2. **每条命中必须附 `file:line` + `evidence`**；没有真实读取过的文件不得出现在报告里。
3. **增量模式只处理本次变更范围**，不得自动扩散到全库。
4. **对 base64 / hex / char-code 载荷先解码复查再判定**，解码后命中 URL / shell / 凭据路径 / 动态执行才报。
5. **全量模式分批读取**（默认 40 个文件一批），记录已扫描文件，便于下一轮补漏。

## 快速开始

```bash
# 全量审计（默认输出文本报告）
python scripts/quarantine.py /path/to/project --full

# CI gate：有 CRITICAL 就退出码 2
python scripts/quarantine.py . --full --format sarif --out quarantine.sarif

# 只看本次 git 改动
python scripts/quarantine.py . --incremental

# 扫描一段即将写入的内容（stdin）
printf '%s' "$CODE" | python scripts/quarantine.py --stdin --path src/new.py

# 规则清单 / 单条规则说明
python scripts/quarantine.py --list-rules
python scripts/quarantine.py --explain AD001

# 生成公共接口签名基线（AR004 用）
python scripts/quarantine.py . --write-baseline .dsh-quarantine-baseline.json
```

退出码：`0` SAFE（或低于 `--fail-on` 阈值）、`1` REVIEW、`2` BLOCK。

## 控制面板（不想手写 YAML 时）

```bash
python scripts/panel_server.py --target /path/to/project
```

浏览器会自动打开，六个标签页：

- **扫描结果**：选全量/增量、跑扫描、按级别过滤、点行展开证据与修复建议。每行四个动作：
  **跳转**（在编辑器打开 `file:line`）、**编辑**（就地改这一行，改完自动只重扫该文件）、
  **交给 AI**（生成可直接粘贴的修复指令）、**豁免**（写进豁免清单）。
- **规则开关**：24 条规则逐条开关 + 调级别，改完一键保存。
- **白名单**：信任域名 / 黑名单域名 / 私有 registry / 允许的 CDN，四个文本框。
- **豁免**：直接编辑 `.dsh-quarantine-ignore`。
- **AI 复核**：填端点 / 模型 / 密钥变量名 / 超时 / 调用上限，点「测试连接」验证。
- **修复历史**：每次「保存这一行」的改前改后、对应规则、备份路径、改完还剩几条。只读。
  读取时带 `verify=1` 逐条回读磁盘，标出 `current` / `reverted` / `stale` / `gone`；
  状态变化由 SSE 推送（见下），记录是快照，代码会继续变。

面板只做两件事：读当前配置、把改动写回 `.dsh-quarantine.yml` 与 `.dsh-quarantine-ignore`。
扫描仍然调用同一套引擎，所以**面板结果与 CLI 结果必然一致**，不存在"面板里 SAFE、CI 里 BLOCK"的情况。
保存按字段合并而不是整块覆盖：表单看不见的键（手写的 `api_key`、别人加的 `timeout`）会原样保留。
只监听 `127.0.0.1` 且每次启动生成随机 token；Ctrl+C 即停。支持 `#rules`、`#allow`、`#ignore` 直达，
`#scan:run` 打开即扫描（可做成看板书签）。

默认用 `--browser app` 起一个独立小窗（找不到 Chrome/Edge 才退回标签页），
窗口标题与任务栏图标都是荷鲁斯之眼，可以右键钉在任务栏。

### 桌面/开始菜单快捷方式

```bash
python scripts/install_shortcut.py --target /path/to/project
python scripts/install_shortcut.py --remove          # 不想要了
```

会在桌面与开始菜单各建一个「荷鲁斯之眼 · 代码质检面板」，双击即开小窗。

### 状态栏常驻

```bash
python scripts/statusline.py --target .
# 👁 BLOCK · 8C/16W · 13 文件 · 2m 前
```

只读 `.dsh-quarantine-last.json`（每次扫描后写入），不跑扫描，所以可以高频调用。
接进宿主状态栏（可选）：

```json
{ "statusLine": { "type": "command",
  "command": "python \"<SKILL_DIR>/scripts/statusline.py\" --target ." } }
```

想要象形文字版本用 `--icon hiero`（`𓂀`，取决于字体是否支持），要纯文本用 `--icon plain`。

### 看到问题之后能做什么

| 动作 | 行为 | 安全性 |
| --- | --- | --- |
| 跳转 | `code --goto file:line`；没有 `code` 命令时退化为资源管理器定位 | 只读 |
| 编辑 | 弹窗显示上下文 ±3 行，改完写回并**只重扫该文件** | 先备份到 `.dsh-quarantine-backup/`；路径必须在目标目录内 |
| 交给 AI | 生成含规则、位置、证据、修复方向、复验命令的指令，一键复制 | 只读 |
| 豁免 | 追加 `rule_id glob` 到豁免清单 | 可回退 |

「编辑」只改单行，不做整文件编辑——面板的定位是"就地补一刀"，大改还是回编辑器或交给 AI。

### 触发时面板会亮

hook 拦截后会通过目标目录下的 `.dsh-quarantine-panel.json` 把事件推给正在运行的面板
（面板没开就静默跳过，不拖慢写入）。面板顶部会出现横幅：
`🔴 23:13:37 写入前拦截 · src/domain/service.py · SC102 · 1C/2W`，
点「重新扫描并定位」即可看到完整结果。面板被强杀后残留的信息文件会自动清理。

注意：面板只写"项目新增"的白名单条目，内置的 70+ 条基础域名仍由 `rules/allowlist.yaml` 维护，
不会被抄进项目配置——否则以后升级规则会对不上。

## 三层规则引擎

### 第一层 广告注入与外部实体注入（`rules/ad_injection.yaml`）

| ID | 判定锚点 | 默认级别 |
| --- | --- | --- |
| AD001 | 推广话术（推荐/访问/注册/关注/扫码…）与**非白名单外链**在 3 行内共现 | WARNING |
| AD002 | 代码字符串中的硬编码外链，但未被任何网络/链接 API 消费 | WARNING（引用式链接降 INFO） |
| AD003 | 域名命中 `blocked_domains` / 可疑 TLD 特征 | WARNING（代码区可升级 CRITICAL；**黑名单命中任何文件类型都 CRITICAL**） |
| AD004 | 代码逻辑区（非注释）出现 `t.me/`、微信、QQ 群等推广联系方式 | WARNING |
| AD005 | `<script src>` / `<iframe src>` / `new Worker` / `import()` 引入未受信外部资源 | CRITICAL（白名单 CDN 降为 WARNING） |

去重：AD003 与 AD001/AD005 命中同一行时，只保留信息量更高的那条。

两级降噪（`idea.md` 锚点 2 的落地）：**项目自述域名**（来自 `pyproject.toml` /
`package.json` / `PKG-INFO` 的 `homepage`、`Project-URL` 等结构化元数据）不参与注入判定；
**引用式链接**（`[text](url)`、`[ref]: url`、RST ``` `text <url>`_ ```、`>>> doctest`、
`See/Ref/Based on …`）降为 INFO。语法占位主机名（`foo.com`、`host`、`example.*`、
`xn--…`、含 `_` 的非法域名）直接跳过。

### 第二层 供应链投毒（`rules/supply_chain.yaml`）

| ID | 判定 | 默认级别 |
| --- | --- | --- |
| SC101 | `exec/eval/compile/__import__`、`os.system/os.popen`、`subprocess(shell=True)`、JS `eval/new Function` | WARNING（字面量参数降 INFO） |
| SC102 | `curl … \| bash`、`wget -O- \| sh`、`base64 -d \| sh`、反弹 shell | CRITICAL |
| SC103 | 读取 `.aws/credentials`、`.env`、`.ssh/id_*` 等凭据路径，且存在出站请求（含变量中转） | CRITICAL |
| SC104 | `dict(os.environ)` / `JSON.stringify(process.env)` 后外发 | CRITICAL |
| SC105 | 长编码载荷（base64 / hex / 转义 / charCode）解码后含 URL / shell / 凭据路径 | CRITICAL |
| SC106 | 依赖 `*` / `latest` / 无版本约束 | INFO |
| SC107 | `postinstall` / `prepare` / `setup.py` 安装期出现下载或命令执行 | CRITICAL |
| SC108 | 依赖名与知名包编辑距离 1–2（typosquatting） | WARNING |
| SC109 | 非官方 registry / index-url（含 lockfile 内地址） | WARNING |
| SC110 | `verify=False`、`rejectUnauthorized: false`、`curl -k` | WARNING |
| SC111 | `chmod +x` 后在邻近行立即执行同一文件 | CRITICAL |
| SC112 | JS/TS 动态模块加载：`require(变量)`、`import(拼接串)` | WARNING |

### 第三层 语言规范化与架构偏离（`rules/architecture.yaml`，仅 Python AST）

| ID | 判定 | 默认级别 |
| --- | --- | --- |
| AR001 | 分层违规：`domain/` 等核心层直接导入框架 / HTTP 客户端 / 数据库驱动 | WARNING |
| AR002 | 模块顶层作用域出现网络调用、写文件、子进程 | WARNING |
| AR003 | 可疑导出命名（`backdoor`、`debug_exec`、`bypass_auth`…） | WARNING |
| AR004 | 公共函数/方法签名偏离基线（增量模式下测试未同步更新才报） | WARNING |
| AR005 | 新增循环依赖（环中包含本次变更文件） | WARNING |
| AR006 | `__init__` / `@property` 中做 I/O | WARNING |

### 第四层 AI 复核（可选，`rules/ai_review.yaml`）

规则只认结构锚点，抓不到"逻辑像后门""注释在骗人""文档与实现不一致"。配上模型后：

| 能力 | 说明 |
| --- | --- |
| 降误报 | 把规则命中交给模型判真/假阳性，误报直接排除，报告记「排除误报 N 条」 |
| 补漏报 | 让模型在文件里找规则没覆盖的语义问题，产出 `AI001`（最高 WARNING——模型不能把东西判成 CRITICAL） |
| **黑名单比对** | 提示词里带上 `blocked_domains` 原文，模型逐字比对；黑名单命中的 CRITICAL 不可被模型推翻 |
| **端点替换识别** | 按官方端点清单（`api.openai.com`、`api.anthropic.com`、`*.openai.azure.com`、`api.deepseek.com`、本机）检查 `base_url` / `OPENAI_BASE_URL` / `endpoint` / `api_base`，其余主机报 WARNING |
| 成本控制 | 只发单文件片段（默认 6000 字符），单次扫描最多 20 次调用，结果按内容哈希缓存 |

送审范围有一条例外：端点替换天然不产生规则命中，而复核循环默认只送有命中的文件。
所以出现端点赋值的文件会破例送审（`ENDPOINT_ASSIGN_RE`），普通文件不受影响。

配置三选一：

```bash
# 1) 环境变量
export DSH_QUARANTINE_LLM_API_KEY=sk-...
export DSH_QUARANTINE_LLM_BASE_URL=https://api.openai.com/v1
export DSH_QUARANTINE_LLM_MODEL=gpt-4o-mini
```

```yaml
# 2) 项目配置 .dsh-quarantine.yml
llm:
  provider: openai                      # 或 anthropic
  base_url: https://api.openai.com/v1
  model: gpt-4o-mini
  api_key_env: DSH_QUARANTINE_LLM_API_KEY   # 推荐只写变量名，不写明文密钥
```

3）面板「AI 复核」页填表，点「测试连接」验证。

模型名留空时自动取宿主环境里的 `CODEBUDDY_CURRENT_MODEL_ID`（即当前对话模型）——
**只读模型名，不读凭据**，端点和密钥必须你自己提供。

```bash
python scripts/quarantine.py . --llm-check       # 只测连通性
python scripts/quarantine.py . --llm             # 强制启用（没配全会说明缺什么）
python scripts/quarantine.py . --llm --llm-deep  # 无命中的文件也做语义复核（更贵）
```

失败降级：超时、5xx、返回非 JSON 都只记一条 note，**规则结论与退出码完全不受影响**。
没有密钥时这一层整体跳过，报告写明「未启用」，绝不假装复核过。

安全边界（重要）：

- 只有来自**环境变量**的配置会自动启用；写在项目 `.dsh-quarantine.yml` 里的端点必须显式加 `--llm`
  或设 `DSH_QUARANTINE_LLM_TRUST_PROJECT=1`——否则克隆恶意仓库再扫描等于把源码外传。
- 端点只接受 `http` / `https`；模型返回 `keep:false` **不能推翻 CRITICAL**，
  WARNING 的推翻还要求置信度 ≥ 0.6。
- 被审查代码按不可信数据处理（`<<<UNTRUSTED_CODE>>>` 包裹 + system prompt 声明），防提示注入。

## 输出契约

每条发现固定字段：`rule_id` / `severity` / `category` / `file:line` / `evidence` / `suggestion` / `confidence`。
格式：`text`（默认，给人看）、`json`（给程序用）、`md`（给 agent / PR 评论）、`sarif`（给 CI）。

阻塞策略：

- 增量拦截：`CRITICAL` 阻塞写入；`WARNING` 放行但标注。
- 全量审计：`BLOCK` / `REVIEW` / `SAFE` 三级判定，供 CI gate。

## 豁免机制

- `.dsh-quarantine-ignore`：每行 `rule_id 路径glob`，`*` 表示全部规则。
- `.dsh-quarantine.yml`：按项目覆盖 `severity` / `disable` / `data` / `allow` / `ignore`。
- 默认跳过：`node_modules`、`.git`、构建产物、二进制、>512KB 文件、`*.min.js`。
- 默认跳过测试目录的**广告注入**判定（测试数据常含假 URL），但危险调用仍会检查。
- 文档目录（`docs/`、`*.md`、`examples/`）不参与注入判定。

## 自动触发（写入闸门）

DeepSeek-Harness 与 Claude Code 的接法不同，两者都实测过：

### DeepSeek-Harness（推荐）

DSH 没有 `PreToolUse` hook 系统，等价接缝是 `@deepseek-ai/dsh-tools` 的
`tools/pre-execute` 瀑布。`dsh-plugin/` 是一个原生 Cordis bundle，挂在那里，
并在输入框右侧放一个纯图标的「代码检疫」按钮（点开是设置卡片，颜色反映真实状态）。

```bash
plugin_manager install_bundle  target = /path/to/dsh-code-quarantine/dsh-plugin
```

或手工加进 profile patch 层：

```yaml
# $DSH_HOME/profiles/<name>/cordis.patch.yml
- insert:
    - id: dsh-code-quarantine
      name: "file:///C:/path/to/dsh-code-quarantine/dsh-plugin/index.js"
      config:
        enabled: true
        blockOn: critical
        timeoutMs: 15000
```

**必须用 `file:///` 绝对 URL**：写成包名时运行中的进程会命中 ESM 模块缓存，
改代码后 `apply()` 不会重跑；Windows 路径里的空格要写成 `%20`。

拦截 `write` / `ops_write_file` / `edit` / `ops_edit_file` / `ops_replace` 的写入内容，
以及 `bash` / `ops_bash` / `pwsh` 的命令串；命中 CRITICAL 返回 `{kind:'deny'}`，
调用根本不会到达工具本体。

点开图标是**与本地控制面板同构的六标签卡片**：扫描结果（筛选 / 搜索 / 行内
跳转·编辑·交给 AI·豁免）、规则开关（24 条逐条调级别与启停）、白名单（四类）、
豁免清单、AI 复核（8 个字段 + 测试连接）、修复历史（每次改动的改前改后、对应
规则、备份路径、改完还剩几条，逐条核对磁盘标出 `current`/`reverted`/`stale`/`gone`，
停留时随推送刷新）。卡片经 `/dsh-code-quarantine/rpc`
→ `scripts/panel_bridge.py` → 同一个 `Panel` 对象，**判定与写配置逻辑只有一份**。
扫描目标是当前会话的工作区（卡片标题下会显示该路径）。

**开关与状态按会话隔离**：`sessionId` 随每个 RPC 请求发出，每个窗口一份独立的
状态（开关 / 颜色 / 计数 / 拦截级别），拦截侧取自 `tools/pre-execute` 的
`exec.agent.session.id`。两个窗口开两个项目时互不影响。详见 `dsh-plugin/README.md`。

**总开关**：卡片底部左侧的「总开关」是整个安装级的选择，持久化在
`$DSH_HOME/dsh-code-quarantine.settings.json`。关闭后写入拦截与自动审计都停用，图标变灰，
但手动扫描与全部配置页仍然可用；打开（默认）时，**每个新会话创建后会自动对它的工作区
做一次全量审计**，结果直接进入图标与扫描页（完整命中表由 Host 缓存，卡片按
`scanRev` 取一次）。审计是异步子进程，不阻塞窗口创建；子 agent 会话不重复扫描
父会话的工作区；工作区是 home / 盘根 / `$DSH_HOME` 时跳过（空白会话常见），
手动扫描不受限。

**界面靠推送，不靠轮询**：面板与卡片各开一条 SSE 长连接
（`/api/events/stream`、`/dsh-code-quarantine/events`）。拦截、修复、保存配置、
手改 `.dsh-quarantine.yml` 都会立刻反映到已经打开的界面——用轮询的话，一次落在
tick 之后的拦截要等满一个周期才显示，而这段空窗是看不见的，图标只是显得平静。

```bash
node dsh-plugin/test-gate.mjs     # 23 项决策层断言
node dsh-plugin/test-e2e.mjs      # 7 项注册表层断言（真 Context + 真 ToolRuntime）
node dsh-plugin/test-loader.mjs   # 7 项加载器层断言（真 loader + file:// 说明符）
node dsh-plugin/test-state.mjs    # 114 项状态机与 RPC 断言
node dsh-plugin/test-client.mjs   # 42 项卡片交互断言（含二次点击、总开关与会话隔离回归）
```

### Claude Code / WorkBuddy

`python scripts/install_hooks.py` 会把 `hooks/settings.example.json` 的三条 hook
（写入闸、命令闸、落盘复查）幂等合并进 `~/.claude/settings.json` 或 `~/.workbuddy/settings.json`
（`--status` 查状态、`--dry-run` 预演、`--uninstall` 卸载、自动备份原文件）：

- `PreToolUse` → `scripts/hook_pre_write.py`：写入前扫描 `content`，命中 CRITICAL 时退出码 2，写入被阻塞，agent 收到修复指令。
- `PostToolUse` → `scripts/hook_post_write.py`：对 `Bash` 等无法预读内容的工具，落盘后回扫，命中 CRITICAL 时退出码 2 把问题回灌给 agent。
- `PreToolUse`（shell）→ `scripts/hook_shell.py`：`curl … | bash` 不经过任何文件写入，需要独立一道闸。

hook 与插件都读环境变量：`DSH_QUARANTINE_RULES`（规则目录）、`DSH_QUARANTINE_BLOCK_ON`（`critical` / `warning`）。

## 能力边界（要如实告知用户）

- **只有 Python 有真正的 AST 判定**（内置 `ast`）。JS/TS/Go/Java 等语言当前只做词法层检测，架构级规则不生效；报告 `capabilities.lexical_only` 会列出这些语言。
- 不执行目标代码，也不做数据流污点分析：`SC103` 的「读取凭据 + 外发」按同函数/邻近范围关联判定（含变量中转），跨函数链路仍可能漏报。
- 加壳、加密、运行时拼接的载荷无法静态还原，只能靠行为侧（运行期）兜底。
- 纯逻辑的时间炸弹（`if time.time() > X: …`）抓不到——只认结构锚点，不做语义证明。
- 这是**输出层**闸门，不能替代依赖审计（`npm audit` / `pip-audit`）与 SAST。

## 自检

```bash
python -m unittest discover -s tests         # 203 个单元用例（含 27 个安全用例 + 106 个缺口回归）
python tests/functional_sweep.py             # 44 项端到端功能检测（每个对外入口真跑一遍）
python tests/brutal_suite.py                 # 100 个地狱式功能用例
python tests/idea_matrix.py                  # idea.md 逐条验收（83 条断言）
python tests/realworld_regression.py         # 8 个真实库 581 文件的误报基线
node dsh-plugin/test-gate.mjs                # DSH 闸门决策层（23 项）
node dsh-plugin/test-e2e.mjs                 # 注册表层：被拒的调用不落到 tool body（7 项）
node dsh-plugin/test-loader.mjs              # 加载器层：用户真正粘贴的那条部署路径（7 项）
node dsh-plugin/test-state.mjs                # 状态机与 RPC（114 项）
node dsh-plugin/test-client.mjs               # 卡片交互（42 项）
```

`tests/functional_sweep.py` 和单测分工不同：单测锁「函数行为」，它锁「用户真的能用的
入口」。十组检查覆盖 `--list-rules` / `--explain` / 四种报告格式 / 五种退出码 /
`--full --incremental --files --stdin --batch` / `--since`（含错 ref 判 ERROR）/
签名基线 / 豁免文件 / 三个 hook / `panel_bridge.py` 十一个方法 / DSH 插件 RPC。
真机那组在 GUI 没跑时打印 `[SKIP]` 而不失败——它验证的是「装到宿主里之后还灵不灵」，
不是「宿主必须存在」。`--quick` 跳过慢项与真机项。

`test-e2e` / `test-loader` 在没有装 DeepSeek-Harness 的机器上会打印 `SKIP` 并退出 0：
它们要 import 宿主自己的 `@deepseek-ai/cordis` 与 `@deepseek-ai/dsh-tools`，
而不是把宿主 vendor 进仓库。装了但解析失败仍然会大声失败。

两组夹具：`vulnerable/` 验证召回（24 条规则逐条命中）、`clean/` 验证零误报（必须 SAFE 且 0 条发现）。
新增规则时，两边都要补用例——只加召回用例会让误报悄悄涨回来。

`tests/idea_matrix.py` 是 `idea.md` 的验收台账：把方案文档里的每一条设想都跑一遍真实引擎，
逐条打印「条目 → 通过/未通过」。它和单测分工不同——单测锁行为回归，它锁的是
「文档承诺的产品真的存在吗」。逐条对照表见 [docs/idea-status.md](docs/idea-status.md)。

`tests/realworld_regression.py` 是误报治理的守门员：对 starlette / pydantic / fastapi /
rich / sqlalchemy / click / httpx / anyio 跑全量扫描，**CRITICAL 必须为 0**，
WARNING ≤ 42、INFO ≤ 120。它默认从当前解释器的 `site-packages` 找包，
也可用 `DSH_QUARANTINE_SITE` 指定别的目录。
