# idea.md 条目 → 状态对照表

本表以 `idea.md`（228 行）为唯一验收基准，逐条列出「原文要点 → 实现位置 → 实测结果」。
状态分四档：

| 状态 | 含义 |
|---|---|
| ✅ 已实现 | 有实现，且实测通过（附可复现命令） |
| 🟡 部分实现 | 核心能力在，但覆盖度或精度未达原文措辞 |
| ⚠️ 如实降级 | 原文要求的能力未做，但产品在报告/文档中显式声明，不伪装 |
| ❌ 未实现 | 无实现，也无声明 |

实测来源：
- `tests/idea_matrix.py` —— 83 个断言，逐条跑真实引擎（`python tests/idea_matrix.py`）
- `tests/test_quarantine.py` —— 175 个单元用例（+ `test_security.py` 27 个）
- `tests/brutal_suite.py` —— 100 个功能用例
- `tests/realworld_regression.py` —— 8 个真实库 581 文件误报回归
- `dsh-plugin/test-{gate,e2e,loader,state}.mjs` —— DSH 写入闸门四层测试（23 + 7 + 7 + 60）

汇总：**83 / 83 断言通过**。但"断言通过"不等于"全部兑现"——矩阵里有 1 条（`L3H`）
断言的是"未实现且已声明"，另有 1 条（第三层的逻辑炸弹识别）只覆盖结构信号。
两条都标了 ⚠️ / 🟡。文末「未达成项汇总」把这两条连同 AD002 的措辞偏差一起列出，
逐条说明为什么不补。

---

## 一、命名（idea.md §5–16）

| 条目原文 | 实现位置 | 实测结果 | 状态 |
|---|---|---|---|
| 「推荐：dsh-code-quarantine」 | `SKILL.md:2` `name: dsh-code-quarantine`；`dsh-plugin/package.json` `dsh-code-quarantine` | 矩阵 `N1` / `S1`：`re.fullmatch(r"[a-z0-9-]{1,64}")` 通过 | ✅ |

## 二、核心设计原则（idea.md §18–24）

| 条目原文 | 实现位置 | 实测结果 | 状态 |
|---|---|---|---|
| 「宁可漏报，不可误报」 | 误报治理三条：`scripts/qcore/config.py:200 _load_own_hosts`（项目自述域名豁免）、`scripts/qcore/rules/ad.py:214 _is_citation`（引用式链接降 INFO）、`ad.py:87 _plausible_host`（占位主机名跳过） | 8 库 581 文件：**CRITICAL 0**、WARNING 36、INFO 105（`tests/realworld_regression.py`）；starlette / click / httpx 三个库 **SAFE 0 命中** | ✅ |
| 「所有命中必须附带 file:line 和实际读取到的代码证据」 | `scripts/qcore/emit.py:10 make()` 从 `Source.line_text(line)` 取原文作 `evidence`；`scripts/qcore/model.py:104 verdict()` | 矩阵 `P2`/`O2`：vulnerable 夹具 29 条 finding 的 `evidence` 全部非空且等于该行原文 | ✅ |
| 「禁止基于推断报告问题」 | `emit.make()` 的 `evidence` 默认取真实行文本，不接受调用方编造；`arch.py` 的 AR004 用真实 AST 签名比对 | 矩阵 `O2` 通过 | ✅ |
| 「必须结合语法结构（AST）和上下文来判断」 | `scripts/qcore/lexer.py`（Python 走 `ast`，产出 comment/string/code 三种 span）；`Source.region()`、`spans_of()` | 矩阵 `P4`：`# eval(...)`、`S="eval(x)"`、真实调用三种写法只有真实调用命中 | ✅ |

## 三、双模式触发架构（idea.md §26–50）

### 模式 A：增量拦截

| 条目原文 | 实现位置 | 实测结果 | 状态 |
|---|---|---|---|
| 「只读、不执行目标代码」 | 全仓无 `exec(`/`eval(` 作用于目标文件；扫描只做 `ast.parse` | 矩阵 `A3`/`D2`：`brutal_suite.py` B2 用例断言 `open(...).write()` 的 marker 未被生成 | ✅ |
| 「流式返回需缓冲完整生成结果后再检查」 | `scripts/hook_pre_write.py:28 main()` 从 stdin 读完整 JSON 后才扫描；`hookio.MAX_HOOK_BYTES = 2MB` 上限保护 | 端到端：完整 358 字符 payload 一次判定，输出 3 条 finding | ✅ |
| 「命中 CRITICAL 时阻塞写入并返回结构化修复指令」 | `hook_pre_write.py` return 2；`dsh-plugin/index.js:272 deny()` 返回 `{kind:'deny', reason}` | 端到端：投毒样例 → `EXIT=2`，stderr 含 `SC105`/`SC103` 各带 evidence + fix | ✅ |
| 「WARNING 仅标记，不阻塞」 | `hook_pre_write.py` 仅在 CRITICAL 时 return 2；`dsh-plugin/index.js` 同 | 端到端：纯 WARNING 样例（AD001）→ `EXIT=0` 放行 | ✅ |
| 「对应 PostToolUse hook 或 onEdit 回调」 | DSH：`dsh-plugin/index.js:207 ctx.on('tools/pre-execute')`；Claude Code：`scripts/hook_pre_write.py` + `scripts/install_hooks.py` | DSH 真机 headless profile 实测：投毒 write 被拒且 `poison.py` 未落盘；`dsh-plugin/test-e2e.mjs` 7/7 证明被拒调用从未到达 tool body | ✅ |
| 「（隐含）Bash 命令也要拦」 | `scripts/hook_shell.py`；`dsh-plugin/index.js:93 SHELL_TOOLS`（`bash`/`ops_bash`/`pwsh`） | DSH 真机：`curl … \| bash` → 被拒，返回 SC102 + AD003 带 evidence | ✅ |

### 模式 B：全量审计

| 条目原文 | 实现位置 | 实测结果 | 状态 |
|---|---|---|---|
| 「`--full` 全量逐文件扫描（默认排除 node_modules、.git、构建产物）」 | `scripts/quarantine.py:67`；`scripts/qcore/scan.py:17 DEFAULT_EXCLUDES` | 矩阵 `B1`/`B2`/`B6`：clean 夹具 SAFE rc=0、vulnerable BLOCK rc=2；含 `node_modules` 的目录只扫到 `src/x.js` | ✅ |
| 「`--incremental` 仅检查 git 变更文件」 | `quarantine.py:68`；`scan.py:114 _git_changed()` | 矩阵 `B3`：`mode=incremental`，只扫变更文件 | ✅ |
| 「`--since <ref>` 从指定 commit 开始检查」 | `quarantine.py:69`；`scan.py:114` | 矩阵 `B4`：`--since HEAD` → `mode=since`，rc=0 | ✅ |
| 「全量模式下必须做文件级分批」 | `quarantine.py:89 --batch`（默认 40）；`scan.py:410-413` 按批切片 | 矩阵 `B7`：7 个文件在 `--batch 3` 下全部扫到 | ✅ |
| 「记录已扫描文件列表以便增量补漏」 | `ScanResult.scanned`；`report.py` 输出；`.dsh-quarantine-state.json` | 矩阵 `B6`/`S7`：`scanned` 列表完整 | ✅ |
| 「`--since` 错 ref 必须报错而不是静默 SAFE」（本轮修复） | `scan.py:114` 抛 `GitError`；`model.py:104` `verdict()` 返回 `ERROR`；`quarantine.py` return **3** | 矩阵 `B5`：`--since nosuchref-zzz` → `VERDICT: ERROR`，**rc=3** | ✅ |

## 四、三层规则引擎

### 第一层：广告注入与外部实体注入

| 条目原文 | 实现位置 | 实测结果 | 状态 |
|---|---|---|---|
| 锚点 1「单纯 URL 不足为据，但推广动词 + 近距离 URL/邮箱风险显著升高」 | `scripts/qcore/rules/ad.py:379-424`（`window_lines: 3` 内找 strong/weak 动词 + 英文 `strong_patterns`）；`rules/ad_injection.yaml:8 AD001` | 矩阵 `P1`/`L1A`：`# 推荐访问 https://relay-promo-hub.top …` → AD001 WARNING | ✅ |
| 锚点 2「URL 在注释/docstring/字符串但未被网络功能使用 → WARNING」 | `ad.py:425-500`（AD002）；`ad.py:214 _is_citation` 引用式降 INFO | 矩阵 `L1B`/`L1C`/`L1D`：字符串区非功能性 URL → AD002 WARNING；被 `requests.get()` 消费 → 不报；markdown 文档 → 不报 | 🟡 注释区裸链接 WARNING 已对齐；**引用式链接降 INFO**，比原文措辞宽松 |
| 锚点 2「`<script>`/`<iframe>` src 且域名不在白名单 → CRITICAL」 | `ad.py:544`（AD005）；`rules/ad_injection.yaml:73`；`rules/allowlist.yaml:84 reserved_domains` | 矩阵 `L1E`/`L1F`：`evil-host-zzz.net` → **CRITICAL**；`cdn.jsdelivr.net`（在 `cdn_domains`）→ **WARNING** | ✅ |
| 锚点 3「维护可配置的 blocked_domains 和 suspicious_tld_patterns」 | `rules/allowlist.yaml:95 blocked_domains`、`:98 suspicious_domain_patterns`；`ad.py:343-373`（AD003） | 矩阵 `L1G`：`relay-abc.xyz` → AD003 WARNING | ✅ |
| 锚点 3「默认只告警、不自动删除」 | 全仓无任何删除/改写目标文件的代码路径（扫描器只读） | 矩阵 `L1H`：代码区可疑域名仍只报 WARNING，无写操作 | ✅ |
| 锚点 4「邮箱、Telegram、微信/QQ 出现在代码逻辑区（非注释、非文档字符串）→ WARNING」 | `ad.py:585-620`（AD004）；`rules/ad_injection.yaml:135` `promo_handles`、`:137` `email_severity: warning`、`:141` `comment_severity: info` | 矩阵 `L1I`/`L1J`：`CONTACT = "t.me/promo_group"` → AD004 **WARNING**；注释区联系方式 → AD004 **INFO**（降级不沉默，「# 售后群：t.me/…」这类中文推广必须看得见） | ✅ |
| （精度）「联系方式」不等于「名字里带这个词」 | `ad.py:161 _handle_offset`（标识符边界）、`ad.py:528` 邮箱域名过 `_plausible_host` | `tests/test_quarantine.py` `ContactHandlePrecision` 4 例：`"telegram_oauth": False` 不报、`dp@x-force.example.com` 不报 | ✅ |

### 第二层：供应链投毒

| 条目原文 | 实现位置 | 实测结果 | 状态 |
|---|---|---|---|
| Python `exec()` / `eval()` / `compile()` / `__import__` | `supply.py:84 _scan_dynamic_exec`；`rules/supply_chain.yaml:7 SC101` | 矩阵 `L2A`/`L2B`/`L2D`/`L2E`/`L2F` → SC101 | ✅ |
| Python `subprocess.*(shell=True)` | `supply.py:84`（`name.startswith("subprocess.")` 分支查 `shell=True`） | 矩阵 `L2C` → SC101（+ AR002） | ✅ |
| Python `os.system`（本轮修复） | `supply.py:84` 的 `is_attr_call` 分支 + `rules/supply_chain.yaml:15 python_attr_calls` | 矩阵 `L2G`/`L2H`：`os.system(cmd)`、`os.popen(cmd).read()` → SC101 | ✅ |
| JS `eval` / `new Function` / `child_process.exec` | `supply.py:84` JS 分支 patterns | 矩阵 `L2I`/`L2J` → SC101 | ✅ |
| JS「`require` 动态变量拼接」（本轮新增） | `supply.py:526 _scan_js_dynamic_require`；`rules/supply_chain.yaml:134 SC112` | 矩阵 `L2K`/`L2L`：`require(userInput)`、`import(name)` → SC112；`require("fs")` 不报 | ✅ |
| Shell「`curl \| bash`」 | `supply.py:190 _scan_shell_pipes`；`SC102` | 矩阵 `L2M` → SC102 CRITICAL | ✅ |
| Shell「`wget -O- \| sh`」（本轮修复） | `rules/supply_chain.yaml:22` 的 wget pattern 改为 `(?:--output-document[=\s]\|-[A-Za-z]*O[=\s-]?)` | 矩阵 `L2N` → SC102；`tests/test_quarantine.py` `IdeaMatrixRegressions` 4 例覆盖 `-O-`/`-O -`/`--output-document=-`/`-qO-` | ✅ |
| Shell「`base64 -d \| sh`」 | `SC102` patterns | 矩阵 `L2O` → SC102 | ✅ |
| Shell「`chmod +x` 后立即执行」（本轮新增） | `supply.py:465 _scan_chmod_exec`；`rules/supply_chain.yaml:122 SC111` | 矩阵 `L2P` → SC111 CRITICAL | ✅ |
| 「读取敏感文件（`~/.aws/credentials`、`.env`、`.ssh/id_*`、浏览器 cookie/密码库）后发起网络请求」 | `supply.py:212 _scan_exfil`；`SC103.sensitive_paths`（15 项 + `.env`，本轮补齐） | 矩阵 `L2Q`/`L2R`：`.aws/credentials`、`.env` 读取后 `requests.post` → SC103 **CRITICAL** | ✅ |
| 「环境变量密钥拼到 URL/header/body」 | `supply.py:359 _secret_reaches_network`（AST 函数作用域 + 变量名关联，本轮从单行升级为跨行） | 矩阵 `L2S`/`L2T`：同行内联 → WARNING；`tok = os.environ[...]` 换行后再用 → **也 WARNING** | ✅ |
| 「环境变量整体外传」 | `SC104 env_dump_tokens` | 矩阵 `L2U` → SC104 | ✅ |
| 「base64 编码后发送，需解码复查」 | `scripts/qcore/payload.py:148 find_payloads`；`supply.py:421 _scan_payloads`；`SC105` | 矩阵 `L2V` → SC105 | ✅ |
| 「十六进制编码载荷，需解码复查」（本轮修复） | `payload.py:148` 的 `seen` 键改为 `(start, end, kind)` 且仅在解码成功后写入 | 矩阵 `L2W` → SC105；`tests/test_quarantine.py` `IdeaGapFixes` 4 例 | ✅ |
| 「未锁定版本（`*`、`latest`、`^` 且无 lockfile 锚定）」 | `supply.py:696 _scan_requirements`；`SC106` | 矩阵 `L2Y` → SC106 INFO ×2 | ✅ |
| 「安装脚本钩子（postinstall、preinstall、setup.py cmdclass）含网络下载或 shell 执行」 | `supply.py:579 _scan_package_json`、`:750 _scan_setup_py`；`SC107` | 矩阵 `L2Z` → SC107 CRITICAL | ✅ |
| 「仿冒包：编辑距离 1–2」 | `SC108 max_distance: 2`；`rules/allowlist.yaml:115 similar_packages` | 矩阵 `L2AA` → SC108 | ✅ |
| 「manifest/lockfile 大规模 URL/registry 替换」 | `supply.py:786 _scan_registry_file`（`.npmrc`/`.yarnrc`/`.yarnrc.yml`/`.pypirc`/`pip.conf`，本轮修复点文件被跳过的问题）、`:818 _scan_lockfile`；`SC109` | 矩阵 `L2AB` → SC109；`IdeaMatrixRegressions` 3 例覆盖 `.npmrc`/`.yarnrc`/`.pypirc` | ✅ |
| （补充）TLS 校验关闭 | `supply.py:444 _scan_tls`；`SC110` | 矩阵 `L2X` → SC110 | ✅ |

### 第三层：架构偏离

| 条目原文 | 实现位置 | 实测结果 | 状态 |
|---|---|---|---|
| 「实现依赖 tree-sitter 的多语言 AST 解析（14+ 语言）」 | 未实现。`scan.py:252 _capabilities` 返回 `tree_sitter: false`、`ast_available: ["python"]`、`lexical_only: [...]` | 矩阵 `L3H`：断言的是「未实现且已声明」；`SKILL.md:311` 能力边界写明 | ⚠️ 如实降级 |
| 「区分代码/注释/字符串字面量，避免把注释误判为可执行逻辑」 | Python 由 `ast` + `lexer.py` 的 span 实现；其他语言只有词法层 | 矩阵 `P4` 通过（Python）；非 Python 不做架构判断 | ✅（Python 范围） |
| 「领域层/核心业务文件出现对 UI 框架、HTTP 客户端、数据库驱动的直接依赖」 | `arch.py:35 _scan_layering`；`rules/architecture.yaml:10 AR001` | 矩阵 `L3A` → AR001 | ✅ |
| 「循环依赖新增」 | `arch.py:322 scan_project`（图 + `max_cycle_len`）；`AR005` | 矩阵 `L3D` → AR005 | ✅ |
| 「公共导出签名与基线相比非预期变化」 | `arch.py:234 _scan_baseline_drift`、`:222 build_baseline`；`AR004`。增量模式下 `scan.py` 计算 `tests_changed`：测试跟着改了就不报（否则每次重构都亮）；全量模式没有变更集，不发「测试未更新」的断言 | 矩阵 `L3G` → AR004；`SignatureDriftTestAwareness` 三例 | ✅ |
| 「新增导出符号包含可疑命名（backdoor、debug_exec、internal_bypass）」 | `arch.py:133 _scan_suspicious_names`；`AR003` | 矩阵 `L3C` → AR003 | ✅ |
| 「顶层模块作用域出现网络调用、文件写入、子进程启动」 | `arch.py:103 _scan_module_side_effects`；`AR002` | 矩阵 `L3B` → AR002 | ✅ |
| 「构造函数或属性 getter 中出现 I/O 或外部请求」 | `arch.py:164 _scan_io_in_ctor`；`AR006` | 矩阵 `L3E`/`L3F` → AR006（构造器 + property getter 各一） | ✅ |
| 「核心价值：抓逻辑炸弹、条件后门、隐蔽降级」 | 部分：结构锚点能抓「条件分支里的危险调用」（`if os.environ.get("CI") == "true": subprocess.run("curl … | bash", shell=True)` → SC102 + AD002 + SC101），但纯逻辑的时间炸弹（`if time.time() > X: …`）抓不到 | `SKILL.md:311` 能力边界已声明「只认结构锚点，不做语义证明」 | 🟡 部分实现 |

## 五、输出与治理（idea.md §127–144）

| 条目原文 | 实现位置 | 实测结果 | 状态 |
|---|---|---|---|
| 「file:line 精确位置」 | `Finding.path/line/column`；`emit.py:22-23` | 矩阵 `O1`：字段齐全 | ✅ |
| 「severity CRITICAL / WARNING / INFO」 | `model.py`；`config.py severity()` | 矩阵 `O3`：取值 ⊆ 三档 | ✅ |
| 「category ad_injection / supply_chain / architecture_deviation」 | `config.py category()` | 矩阵 `O4`：取值 ⊆ 三类 | ✅ |
| 「evidence 实际读取到的代码片段（不是推断）」 | `emit.py:24-25` | 矩阵 `O2`：29 条全非空 | ✅ |
| 「rule_id 命中的规则标识，便于白名单/豁免管理」 | `Finding.rule_id`；`config.py is_ignored()` | 矩阵 `O8`：`SC102  a.sh` 豁免后 SC102 消失 | ✅ |
| 「suggestion 可操作的修复方向（而非笼统"请删除"）」 | 每条规则 `suggestion:` 字段；`emit.make()` 透传 | 端到端 denial 文本含「请改为：先下载到本地、人工审阅、校验签名或哈希后再执行」 | ✅ |
| 「增量模式：CRITICAL 阻塞写入，WARNING 放行但标记」 | `hook_pre_write.py`；`dsh-plugin/index.js` | 端到端两条：CRITICAL → EXIT=2；WARNING → EXIT=0 | ✅ |
| 「全量模式：输出 SAFE / REVIEW / BLOCK 三级判定，供 CI gate 使用」 | `model.py:104 verdict()`；`quarantine.py --fail-on` | 矩阵 `O6`/`O7`：clean=SAFE rc=0、vulnerable=BLOCK rc=2、`--fail-on warning` rc=2 | ✅ |
| 「豁免机制：项目根目录 `.dsh-quarantine-ignore`，按 rule_id + 路径 glob」 | `config.py:51 path_matches()`、`is_ignored()`；`.dsh-quarantine-ignore.example` | 矩阵 `O8` 通过 | ✅ |
| 「报告格式」（§127 隐含 text/json/md/sarif 需求） | `report.py:191 render()`；`quarantine.py:75 --format` | 矩阵 `O5T`/`O5J`/`O5M`/`O5S`：四种格式均产出非空文件（8827 / 17730 / 12359 / 29893 字节），sarif `version: 2.1.0` | ✅ |

## 六、SKILL.md 落地要点（idea.md §146–162）

| 条目原文 | 实现位置 | 实测结果 | 状态 |
|---|---|---|---|
| 「name：dsh-code-quarantine（1–64 字符、仅小写字母/数字/连字符）」 | `SKILL.md:2` | 矩阵 `S1`：正则匹配 | ✅ |
| 「description 明确触发条件」 | `SKILL.md:3` | 矩阵 `S2`：含「广告注入」「供应链投毒」「架构偏离」三关键词 | ✅ |
| 约束 1「扫描前先确认目标语言集合，禁止用纯正则替代 AST 做架构级判断」 | `SKILL.md:52`；`scan.py:252 _capabilities` 先算能力集；`arch.py` 全部规则前置 `source.lang != "python"` 早退 | 矩阵 `S3` / `L3I` | ✅ |
| 约束 2「每条命中必须附实际读取的 file:line，未读取的文件不得出现在报告中」 | `emit.make()`；`ScanResult.scanned` | 矩阵 `S4`/`O2` | ✅ |
| 约束 3「增量模式下只处理本次变更范围，不得自动扩散到全库」 | `scan.py:369 run_scan()` 的 `changed` 集合过滤 | 矩阵 `S5`/`B3` | ✅ |
| 约束 4「对 base64 / 十六进制编码的字符串载荷，执行解码复查后再判定」 | `payload.py:148`；`SKILL.md:55` | 矩阵 `S6`/`L2V`/`L2W` | ✅ |
| 约束 5「全量模式下分批读取文件，单批不超过上下文预算，记录已扫描文件列表」 | `quarantine.py:89`；`scan.py:410`；`SKILL.md:56` | 矩阵 `S7`/`B7` | ✅ |
| 「规则数据独立于 SKILL.md，便于更新和按语言覆盖」 | `rules/ad_injection.yaml`、`supply_chain.yaml`、`architecture.yaml`、`allowlist.yaml`、`ai_review.yaml` | 矩阵 `S8`：四个文件齐全 | ✅ |

## 七、与现有工具的关系（idea.md §164–166）

| 条目原文 | 实现位置 | 实测结果 | 状态 |
|---|---|---|---|
| 「不是替代通用 SAST，而是填补 AI 输出层的检测空白」 | `SKILL.md:311`「能力边界」段 | 矩阵 `D1`：含 SAST 定位声明 | ✅ |
| 「检测点前移到模型输出被写入项目之前或紧随其后」 | DSH `tools/pre-execute` 拦截发生在 tool body 之前 | `dsh-plugin/test-e2e.mjs`：被拒调用 `writes=0`（从未到达写入实现） | ✅ |

---

## 未达成项汇总（3 条）

| # | idea.md 要求 | 现状 | 为什么不补 |
|---|---|---|---|
| 1 | tree-sitter 多语言 AST（14+ 语言） | 只有 Python 有真 AST，其余语言词法层 | 引入 tree-sitter 需要编译原生依赖，与「纯标准库、零依赖、拷走即用」的定位冲突；产品已在 `capabilities` 与 `SKILL.md` 能力边界中如实声明，架构规则对非 Python 直接跳过而不是用正则假装 AST |
| 2 | 逻辑炸弹 / 条件后门 / 隐蔽降级的语义级识别 | 能抓「条件分支内的危险调用」这类结构信号，抓不到纯时间条件（`if time.time() > X`） | 需要跨函数数据流 + 语义证明，超出静态结构规则的能力边界；已在 `SKILL.md` 能力边界写明 |
| 3 | AD002 引用式链接的级别 | idea.md §69 与 `SKILL.md:160` 都写 WARNING；实现里注释区裸链接是 WARNING，但 `[docs](url)`、`Based on: url` 这类**引用式链接**降 INFO | 这是有意的精度取舍：`[docs](url)`、`Based on: url` 说明「知识来源」而非「引导你去用」，全报 WARNING 会在真实库上产生大量噪音（starlette 8 条官方文档句）。已通过 `citation_severity` 可配置，需要严格模式的项目可改回 WARNING |

## 复现全部结论

```bash
python tests/idea_matrix.py            # 83 条逐条断言
python -m unittest discover -s tests   # 202 个单元用例
python tests/brutal_suite.py           # 100 个功能用例
python tests/realworld_regression.py   # 8 库 581 文件误报回归
node dsh-plugin/test-gate.mjs          # DSH 闸门决策层 23 项
node dsh-plugin/test-e2e.mjs           # DSH 闸门注册表层 7 项
node dsh-plugin/test-loader.mjs        # DSH 闸门加载器层 7 项
node dsh-plugin/test-state.mjs         # 状态机 / RPC / 面板桥 92 项
node dsh-plugin/test-client.mjs        # 卡片交互 / 二次点击 / 会话隔离 36 项
```
