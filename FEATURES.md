# 功能清单与成熟度

> **v1.1.0** · 24 条规则 · 引擎 7,447 行 · 测试 5,989 行 · 支持 23 种代码语言
> 最后更新：2026-10-22

## 一句话

在「AI 生成的代码被写进项目」这一刻拦一道，把广告注入、供应链投毒、架构偏离挑出来，
并且**点得动**：能跳到行、能就地改、能一键生成给 AI 的修复指令。

---

## 1. 能力地图

| 模块 | 做了什么 | 状态 |
| --- | --- | --- |
| **检测引擎** | 三层规则 + AI 复核，24 条规则，语言感知（区分注释/字符串/代码） | ✅ 生产可用 |
| **双模式入口** | 写入前阻塞（hook）/ 全量审计（CLI） | ✅ 生产可用 |
| **交互面板** | 扫描、规则开关、白名单、豁免、AI 配置；逐条 跳转/编辑/交办/豁免。浏览器小窗与 Harness 卡片两个入口共用同一套 `Panel` | ✅ 生产可用 |
| **实时拦截回显** | hook 拦截 → 推给面板 → 顶部红色横幅 | ✅ 可用 |
| **Harness 写入闸门** | DSH 原生 bundle：写入/命令落盘前拦截 + 输入框图标 + 六标签卡片 | ✅ 生产可用 |
| **AI 复核** | 降误报 + 补漏报，双协议、自动识别对话模型、缓存、防注入 | 🟡 可用待联调 |
| **报告与 CI** | text / json / md / sarif，退出码 0/1/2（规则缺失或错 ref 为 3） | ✅ 生产可用 |
| **状态栏** | `👁 BLOCK · 8C/16W · 13 文件 · 2m 前` | ✅ 可用 |
| **桌面入口** | 荷鲁斯之眼图标快捷方式 + 独立小窗 | ✅ Windows 可用 |

---

## 2. 检测能力（24 条）

### 第一层 · 广告注入（5 条）

| ID | 判定锚点 | 级别 |
| --- | --- | --- |
| AD001 | 推广话术（推荐/访问/注册/扫码…）与**非白名单外链** 3 行内共现 | WARNING |
| AD002 | 代码字符串里的硬编码外链，但没被任何网络/链接 API 消费 | WARNING |
| AD003 | 域名命中黑名单 / 可疑 TLD 特征（`.top`/`.xyz`/`.icu`…） | WARNING（代码区可升 CRITICAL） |
| AD004 | 代码逻辑区出现 `t.me/`、微信、QQ 群等推广联系方式 | WARNING |
| AD005 | `<script src>` / `<iframe>` / `new Worker` / `import()` 引入未受信资源 | CRITICAL（白名单 CDN 降 WARNING） |

### 第二层 · 供应链投毒（12 条）

| ID | 判定 | 级别 |
| --- | --- | --- |
| SC101 | `exec/eval/compile/__import__`、`os.system/os.popen`、`subprocess(shell=True)`、JS `eval/new Function` | WARNING（字面量参数降 INFO） |
| SC102 | `curl … \| bash`、`wget -O- \| sh`、`base64 -d \| sh`、反弹 shell | CRITICAL |
| SC103 | 读 `.aws/credentials`、`.env`、`.ssh/id_*` 等凭据路径，且存在出站请求（含变量中转） | CRITICAL |
| SC104 | `dict(os.environ)` / `JSON.stringify(process.env)` 后外发 | CRITICAL |
| SC105 | base64 / hex / charCode 载荷解码后含 URL / shell / 凭据路径 | CRITICAL |
| SC106 | 依赖 `*` / `latest` / 无版本约束 | INFO |
| SC107 | `postinstall` / `prepare` / `setup.py` 安装期下载或执行 | CRITICAL |
| SC108 | 依赖名与知名包编辑距离 1–2（typosquatting） | WARNING |
| SC109 | 非官方 registry / index-url（含 lockfile 内地址） | WARNING |
| SC110 | `verify=False`、`rejectUnauthorized: false`、`curl -k` | WARNING |
| SC111 | `chmod +x` 后在邻近行立即执行同一文件 | CRITICAL |
| SC112 | JS/TS 动态模块加载：`require(变量)`、`import(拼接串)` | WARNING |

### 第三层 · 架构偏离（6 条，仅 Python AST）

| ID | 判定 | 级别 |
| --- | --- | --- |
| AR001 | `domain/` 等核心层直接导入框架 / HTTP 客户端 / 数据库驱动 | WARNING |
| AR002 | 模块顶层出现网络调用、写文件、子进程 | WARNING |
| AR003 | 可疑导出命名（`backdoor`、`debug_exec`、`bypass_auth`…） | WARNING |
| AR004 | 公共函数/方法签名偏离基线 | WARNING |
| AR005 | 循环依赖（增量模式下只报含变更文件的环） | WARNING / INFO |
| AR006 | `__init__` / `@property` 里做 I/O | WARNING |

### 第四层 · AI 复核（1 条）

| ID | 判定 | 级别 |
| --- | --- | --- |
| AI001 | 规则没命中、但模型判断存在语义级问题（推广塞注释、隐蔽外发、条件后门） | 最高 WARNING（模型不能定 CRITICAL） |

---

## 3. 入口（四层）

| 入口 | 位置 | 说明 |
| --- | --- | --- |
| 斜杠 | 对话输入框内 | `/dsh-code-quarantine` |
| 小窗 | 桌面/任务栏 | Chrome app 模式独立窗口，荷鲁斯之眼图标，可钉住 |
| 状态栏 | 对话界面底部 | 常驻一行判定摘要，只读缓存、秒开 |
| 快捷方式 | 桌面 + 开始菜单 | 「荷鲁斯之眼 · 代码质检面板」 |

---

## 4. 交互闭环

```
写入代码 ──▶ hook 拦截（CRITICAL 阻塞）──▶ 面板横幅亮起
                                            │
            扫描结果 ──▶ 跳转 file:line ────┤
                       就地改这一行 ────────┤──▶ 只重扫该文件，告诉你还剩几条
                       生成 AI 修复指令 ────┤
                       登记豁免 ────────────┘
```

| 动作 | 实现细节 |
| --- | --- |
| 跳转 | `code --goto file:line:1`，无 `code` 命令退化为资源管理器定位 |
| 编辑 | 上下文 ±3 行弹窗，写前备份到 `.dsh-quarantine-backup/`，原子写，改完自动复扫 |
| 交给 AI | 生成含规则/位置/证据/修复方向/复验命令的指令，一键复制 |
| 豁免 | 追加 `rule_id glob` 到 `.dsh-quarantine-ignore` |

---

## 5. 工程能力

| 能力 | 说明 |
| --- | --- |
| 配置分层 | 规则数据（`rules/*.yaml`）→ 项目配置（`.dsh-quarantine.yml`）→ 环境变量 |
| 豁免 | `rule_id + 路径 glob`，`*` 表示全部规则 |
| 增量 | `--incremental`（git diff，非 git 目录回退到 mtime）/ `--since` / `--files` |
| 基线 | `--write-baseline` 记录公共接口签名，AR004 比对漂移 |
| 报告 | text / json / md / sarif；退出码 0/1/2 供 CI gate |
| 成本控制 | AI 调用上限 20 次/扫描，单文件 6000 字符，内容哈希缓存 |
| 零依赖 | 纯标准库；PyYAML 有则用、无则走内置解析器（有测试保证两者一致） |

---

## 6. 实测数据

| 语料 | 规模 | 结果 |
| --- | --- | --- |
| 恶意夹具 | 13 文件 | `BLOCK`，24 条规则逐条命中 |
| 干净夹具 | 10 文件 | `SAFE`，**0 条发现** |
| 合成 HTML 推广页（测试内联） | 运行时构造 | `REVIEW`，推广话术、属性值与文本节点外链均被检出 |
| 8 个真实库（starlette/pydantic/fastapi/rich/sqlalchemy/click/httpx/anyio） | 581 个 .py | **0 CRITICAL** / 36 WARNING / 105 INFO（`tests/realworld_regression.py` 锁定上限） |
| CPython 3.13 `Lib/` | 537 个 .py | 0 CRITICAL / 11 WARNING（逐条核对均真阳性：`shell=True`、`exec(open().read())`、`eval(request)` 等） |
| npm 源码 `npm/lib` | 110 个 .js | `SAFE`，0 WARNING |
| 本项目自检 | 57 文件 | `SAFE`，0 条发现 |

**测试**：188 个单元用例（含 27 个安全用例）+ 44 项端到端功能检测 + 100 个地狱式功能用例
+ 83 条 idea.md 逐条验收 + 5 个 DSH 插件套件（23/7/7/62/17），全绿。

---

## 7. 成熟度评估（诚实版）

图例：🟢 生产可用 · 🟡 可用待验证 · 🟠 实验性 · ⚪ 未覆盖

| 模块 | 级别 | 依据 | 风险 |
| --- | --- | --- | --- |
| 规则引擎 · Python | 🟢 | 537 文件实测 0 误报 CRITICAL；AST 判定 | 极少数跨函数数据流会漏 |
| 规则引擎 · JS/TS | 🟡 | 110 文件 0 误报；但只有词法层 | 复杂语法（JSX、装饰器）可能漏 |
| 规则引擎 · Go/Java/Rust/PHP/Ruby | 🟡 | 词法扫描器已覆盖，无实机语料 | 注释边界识别可能有偏差 |
| 架构检查（AR 系列） | 🟢 | 仅 Python，AST + 导入图 | 非 Python 语言不生效（报告中声明） |
| HTML / Vue / Svelte 等标记语言 | 🟡 | 属性值与文本节点按字符串参与判定（`lexer._scan_markup`），复刻页实测 8 条真阳性 | 模板语法（`{{ }}`、`v-if`）里的动态拼接不做求值 |
| AI 复核 | 🟠→🟡 | 协议、降级、缓存、防注入、越权推翻全部有测试 | **未与真实模型联调**，回复格式可能有偏差 |
| 面板 | 🟢 | 26 个安全用例 + 并发 + 穿越 + 原子写 + 六标签（含修复历史） | 同机进程可读 token（同机即同权限） |
| hook | 🟢 | 退出码语义按协议实现；三个闸在真机 headless 会话里跑通完整链路 | 依赖宿主把 payload 按约定送进来 |
| Harness 写入闸门（`dsh-plugin/`） | 🟢 | 真机 desktop profile 上拦截生效：投毒写入被拒且未落盘，shell 管道被拒；5 个 node 套件全绿 | 需要宿主支持 `tools/pre-execute`；缺扫描器时降级为「可见的不可用」 |
| 状态栏 / 快捷方式 | 🟡 | Windows 实机验证 | macOS / Linux 未验证 |
| 跨平台 | 🟡 | Windows 全绿 | Linux 分支（`xdg-open`、chmod、`/dev/tcp`）只在代码层覆盖 |
| CI | 🟡 | workflow 已配 5 个 Python 版本 × 2 平台 + 4 个 job | **尚未首次运行**（目录还不是 git 仓库） |

---

## 8. 明确做不到的

- **不执行目标代码**，也不做跨函数污点分析：`SC103` 的"读凭据 + 外发"按同函数/邻近范围关联。
- **加密、运行时拼接的载荷**静态不可还原，需要运行期行为侧兜底。
- **不替代** SAST / 依赖审计（`npm audit`、`pip-audit`），只守"输出被写进项目"这一道门。
- **Lua** 没有专门词法扫描器，注释区会被当代码（漏报，不误报）。
- **纯逻辑的时间炸弹**抓不到：`if time.time() > X: …` 只认结构锚点，不做语义证明。
- **Skill 本身无法往对话输入框注入按钮**——那是宿主扩展点。但配套的 `dsh-plugin/`
  是一个真正的 DSH bundle，可以注册 `conversation.input.right` 槽位，所以装上插件后
  输入框右侧会有「代码检疫」图标；只装 skill 时能给的仍只有斜杠入口。

---

## 9. 下一步（按性价比）

| 优先级 | 事项 | 为什么 |
| --- | --- | --- |
| P0 | 配一次真实模型跑 `--llm-check` + 全量扫描 | AI 层唯一没被真实验证的环节 |
| P0 | `git init` + 首次 push，让 CI 真跑一次 | 跨平台结论目前是"代码层推断" |
| P1 | 在真实宿主会话里跑一轮 hook | 验证阻塞/回灌的实际体验 |
| P2 | 补 Lua / Kotlin 等语言的词法细节 | 减少漏报 |
| P3 | 规则包支持外部目录热插拔（`--rules` 已支持，缺文档） | 让团队能加私有规则 |
