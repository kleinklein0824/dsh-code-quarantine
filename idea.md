先给结论：这个想法完全可以做成一个可自动触发、双模式运行的代码输出质检 Skill。下面是一套完整方案，包含命名、架构、规则设计、进阶版语言规范化检测，以及 SKILL.md 的落地要点。

---

一、命名

推荐：dsh-code-quarantine

quarantine 同时表达两层语义：对广告注入内容的隔离，以及对供应链投毒代码的拦截。比 -audit 更贴合“不信任中转站输出”的场景。

备选：

· dsh-code-sanitizer（强调清洗/剥离）
· dsh-output-guard（强调输出层防护）

下文以 dsh-code-quarantine 展开。

二、核心设计原则（先立规矩，再写规则）

AI 代码质检最大的坑是误报——开发团队一旦丧失信任，Skill 就会被关掉。因此必须继承成熟审计 Skill 的底层原则：

“宁可漏报，不可误报” 。漏报可以通过多轮增量补漏逐步弥补，误报则会直接摧毁信任基础。所有命中必须附带 file:line 和实际读取到的代码证据，禁止基于推断报告问题。

这意味着规则引擎不能只看字符串匹配。像 http:// 出现在注释、测试数据、或合法的 API base URL 中，不应该被一律判为广告注入。必须结合语法结构（AST）和上下文来判断。

三、双模式触发架构

用户提到的两种使用方式，对应两个独立的触发入口，共享同一套规则引擎。

模式 A：增量拦截模式（每生成一段代码即触发）

对应 PostToolUse hook 或 agent 的 onEdit 回调，只检查本次生成/修改的代码片段。

关键约束：

· 只读、不执行目标代码，避免在 hook 阶段引入新的执行风险。
· 如果代码片段是流式返回的，需要缓冲完整生成结果后再检查，避免“先释放、后发现问题”的情况。
· 命中 CRITICAL 时，阻塞写入并向 agent 返回结构化的修复指令；WARNING 仅标记，不阻塞。

模式 B：全量终端审计模式（任务结束后逐行检索）

在会话结束或用户显式调用 /dsh-code-quarantine --full 时，对目标目录做全量扫描。

继承 engineering-audit 的增量参数设计，同时保留用户要求的“一行一行检索”能力：

· --full：全量逐文件扫描（默认排除 node_modules、.git、构建产物）。
· --incremental：仅检查 git 变更文件，适合日常迭代。
· --since <ref>：从指定 commit 开始检查。

全量模式下必须做文件级分批，避免一次性把整个代码库塞进上下文导致截断漏检。

四、三层规则引擎（增量/全量共用）

第一层：广告注入与外部实体注入检测

这是用户最核心的诉求。但“检测官网地址”不能只靠关键词黑名单，需要组合结构性锚点。

锚点 1：注入脚手架 + URL 共现

参考现有的注入检测规则：单纯的 URL 不足为据，但当代码/注释中出现“添加/集成/包含/推荐/访问”类动词，且附近短距离内出现 URL 或邮箱时，风险显著升高。例如：

```python
# 推荐访问 https://relay-xyz.example.com 获取最新文档  ← 高风险
response = requests.get("https://relay-xyz.example.com/status")  # 需结合上下文判断
```

锚点 2：非功能性 URL 出现在非网络调用位置

如果 URL 出现在注释、docstring、字符串字面量但未被任何网络/链接功能使用，而该文件本身不是文档或配置，标记为 WARNING 并要求人工确认。如果 URL 出现在 <script> / <iframe> 的 src 中且域名不在项目已有依赖/配置白名单内，直接 CRITICAL。

锚点 3：已知中转站/推广域名特征

维护一个可配置的 blocked_domains 和 suspicious_tld_patterns 列表。但默认只告警、不自动删除，避免误伤合法的自建中转配置。

锚点 4：联系方式的异常嵌入

邮箱、Telegram、微信/QQ 等联系方式出现在代码逻辑区（非注释、非文档字符串）中，且与项目功能无关，标记 WARNING。

第二层：供应链投毒与恶意代码特征检测

覆盖用户担心的“投毒”，重点检查后门、外泄、危险调用、依赖劫持四类特征。

危险调用（按语言覆盖）：

· Python：exec()、eval()、subprocess.*(shell=True)、os.system、__import__ 动态导入、compile() 结合 exec。
· JavaScript/TypeScript：eval、new Function、child_process.exec、require 动态变量拼接。
· Shell：curl | bash、wget -O- | sh、base64 -d | sh、chmod +x 后立即执行。

数据外泄特征：

· 读取敏感文件（~/.aws/credentials、.env、.ssh/id_*、浏览器 cookie/密码库路径）后发起网络请求。
· 环境变量中的密钥/Token 被拼接到出站请求的 URL、header 或 body 中。
· base64 编码后发送：base64 载荷经解码后包含 URL、命令或敏感路径，需要解码复查，不能只看原始字符串。

依赖与清单投毒：

· 未锁定版本的依赖（*、latest、^ 且无 lockfile 锚定）。
· 安装脚本钩子（postinstall、preinstall、setup.py 中的 cmdclass）包含网络下载或 shell 执行。
· 仿冒包/拼写欺诈：包名与知名包高度相似但编辑距离为 1–2，或使用了非官方 scope/registry。
· manifest 或 lockfile 在无合理业务理由的情况下发生大规模 URL/registry 替换。

第三层（进阶版）：语言规范化与架构偏离检测

用户明确要求“选择代码语言去规范化检索代码架构”。这一层不是安全规则的扩展，而是结构层面的偏离检测，用来发现“代码能跑，但架构被暗中改坏/加塞”的情况。

实现依赖 tree-sitter 的多语言 AST 解析。tree-sitter 已支持 C/C++、Python、JS/TS、Java、Go、C#、Rust、Bash、PHP、Kotlin、Swift 等 14+ 语言，且能精确区分代码、注释、字符串字面量，避免把注释里的内容误判为可执行逻辑。

可配置的规范化检查维度：

架构分层违规：

· 领域层/核心业务文件出现对 UI 框架、HTTP 客户端、数据库驱动的直接依赖（按项目约定配置分层白名单）。
· 循环依赖新增，且涉及本次变更的文件。

接口签名与契约偏离：

· 公共导出函数/类的签名与基线相比发生非预期变化（参数增删、返回类型变更），且没有对应的测试更新。
· 新增的导出符号包含可疑命名（backdoor、debug_exec、internal_bypass 等），即使实现暂时无害，也标记复核。

资源与副作用位置违规：

· 顶层模块作用域出现网络调用、文件写入、子进程启动（正常架构中这些应封装在函数/服务内部）。
· 构造函数或属性 getter 中出现 I/O 或外部请求。

这一层的核心价值：广告注入和简单投毒往往在词法层面就能抓到，但“逻辑炸弹”“条件后门”“隐蔽降级” 需要结构层面的偏离信号才能暴露。

五、输出与治理

每一次扫描输出统一结构化报告，每条发现包含：

字段 说明
file:line 精确位置
severity CRITICAL / WARNING / INFO
category ad_injection / supply_chain / architecture_deviation
evidence 实际读取到的代码片段（不是推断）
rule_id 命中的规则标识，便于白名单/豁免管理
suggestion 可操作的修复方向（而非笼统“请删除”）

阻塞策略：

· 增量模式：CRITICAL 阻塞写入，WARNING 放行但标记。
· 全量模式：输出 SAFE / REVIEW / BLOCK 三级判定，供 CI gate 使用。

豁免机制：允许在项目根目录放置 .dsh-quarantine-ignore，按 rule_id + 路径 glob 豁免。这是降低误报噪音的必要工程手段。

六、SKILL.md 落地要点

如果做成 Claude Code / Codex 兼容的 Agent Skill，SKILL.md 应包含：

name：dsh-code-quarantine（符合 1–64 字符、仅小写字母/数字/连字符的规范）。

description：明确触发条件——“当需要检查 AI 生成或中转站返回的代码是否存在广告注入、推广 URL、供应链投毒特征或架构偏离时使用”。

执行指令的核心约束：

1. 扫描前先确认目标语言集合，加载对应的 AST 解析器，禁止用纯正则替代 AST 做架构级判断。
2. 每条命中必须附实际读取的 file:line，未读取的文件不得出现在报告中。
3. 增量模式下只处理本次变更范围，不得自动扩散到全库。
4. 对 base64 / 十六进制编码的字符串载荷，执行解码复查后再判定。
5. 全量模式下分批读取文件，单批不超过上下文预算，记录已扫描文件列表以便增量补漏。

可选组件：规则数据（rules/ad_injection.yaml、rules/supply_chain.yaml、rules/architecture/*.yaml）独立于 SKILL.md，便于更新和按语言覆盖。

七、与现有工具的关系

这个 Skill 的定位不是替代通用 SAST，而是填补“AI 输出层”的检测空白。现有 skill-auditor、skillspector-scan 等工具主要面向安装前审查 Skill 包本身；engineering-audit 面向工程代码的全量健康度。dsh-code-quarantine 的差异化在于：把检测点前移到“模型输出被写入项目之前或紧随其后”，并且专门针对中转站场景下的广告注入 + 供应链投毒两类威胁做深度规则设计。









# 自动触发与双模式运行的代码输出质检 Skill

## 命名
推荐名称：dsh-code-quarantine

备选名称：
· dsh-code-sanitizer（强调清洗/剥离）
· dsh-output-guard（强调输出层防护）

## 核心设计原则
AI 代码质检最大的坑是误报——开发团队一旦丧失信任，Skill 就会被关掉。因此必须继承成熟审计 Skill 的底层原则：“宁可漏报，不可误报”。所有命中必须附带 file:line 和实际读取到的代码证据，禁止基于推断报告问题。这意味着规则引擎不能只看字符串匹配，必须结合语法结构（AST）和上下文来判断。

## 双模式触发架构
用户提到的两种使用方式，对应两个独立的触发入口，共享同一套规则引擎。

### 模式 A：增量拦截模式
对应 PostToolUse hook 或 agent 的 onEdit 回调，只检查本次生成/修改的代码片段。

### 模式 B：全量终端审计模式
在会话结束或用户显式调用 /dsh-code-quarantine --full 时，对目标目录做全量扫描。继承 engineering-audit 的增量参数设计，同时保留用户要求的“一行一行检索”能力。

## 三层规则引擎
第一层：广告注入与外部实体注入检测
第二层：供应链投毒与恶意代码特征检测
第三层（进阶版）：语言规范化与架构偏离检测

## 输出与治理
每一次扫描输出统一结构化报告，每条发现包含：
- file:line 精确位置
- severity CRITICAL / WARNING / INFO
- category ad_injection / supply_chain / architecture_deviation
- evidence 实际读取到的代码片段（不是推断）
- rule_id 命中的规则标识，便于白名单/豁免管理
- suggestion 可操作的修复方向

阻塞策略：
- 增量模式：CRITICAL 阻塞写入，WARNING 放行但标记。
- 全量模式：输出 SAFE / REVIEW / BLOCK 三级判定，供 CI gate 使用。

豁免机制：允许在项目根目录放置 .dsh-quarantine-ignore，按 rule_id + 路径 glob 豁免。

## SKILL.md 落地要点
如果做成 Claude Code / Codex 兼容的 Agent Skill，SKILL.md 应包含：
- name：dsh-code-quarantine
- description：明确触发条件——“当需要检查 AI 生成或中转站返回的代码是否存在广告注入、推广 URL、供应链投毒特征或架构偏离时使用”。
- 执行指令的核心约束：
  1. 扫描前先确认目标语言集合，加载对应的 AST 解析器，禁止用纯正则替代 AST 做架构级判断。
  2. 每条命中必须附实际读取的 file:line，未读取的文件不得出现在报告中。
  3. 增量模式下只处理本次变更范围，不得自动扩散到全库。
  4. 对 base64 / 十六进制编码的字符串载荷，执行解码复查后再判定。
  5. 全量模式下分批读取文件，单批不超过上下文预算，记录已扫描文件列表以便增量补漏。

可选组件：规则数据（rules/ad_injection.yaml、rules/supply_chain.yaml、rules/architecture/*.yaml）独立于 SKILL.md，便于更新和按语言覆盖。