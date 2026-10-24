# 复刻页检测记录：d1api.xin 首页

这份记录回答一个问题：**给一段真实的「中转站首页」内容，这套规则到底能不能判对。**

测试对象不是虚构的样本，而是 `https://d1api.xin/` 首页的逐字复刻：

| 项目 | 内容 |
| --- | --- |
| 复刻页 | `demo/d1api-home.html` |
| 复刻来源 | `https://d1api.xin/` |
| 抓取方式 | headless Chrome（`channel="chrome"`，1440×1200，`wait_until="networkidle"`）渲染后取 `body.innerText` |
| 可见文字 | 299 字符（逐字写入页面 `<code>` 块，见页面底部「本页文字全文」） |
| 原始 HTML | 1533 字节的 New API SPA 空壳（`<div id="root">` + 5 个 JS + 2 个 CSS + Cloudflare beacon），文字全靠运行时渲染 |
| 页面元素 | 1 个 `H1`、3 个 `H2`、1 个 `<code>`、16 条 `<a>`（含重复） |

## 为什么用这个页面当夹具

它不是「随便一个网页」。它同时具备这套规则要处理的三种形态：

1. **推广话术与外链共现**（锚点 1）——「购买套餐 / 充值：发卡网购买链接」+
   `https://catfk.com/shop/...`；「售后群：点击加入售后交流群」+ `https://qm.qq.com/q/...`。
2. **非功能性硬编码外链**（锚点 2）——「接口地址：`https://d1api.xin/v1`」直接写死在正文里。
3. **外部实体**（AD005 的反面）——页面上没有任何 `<script src>` / `<iframe src>`，
   所以 AD005 **不应该**报。这是「不误报」那一半的验证。

而它的语言是 HTML —— 恰好是**本轮之前完全测不到**的语言。

## 第一次扫：SAFE 0/0/0

```bash
python scripts/quarantine.py demo/d1api-home.html --full --no-color
```

```
dsh-code-quarantine 1.0.0  |  mode=full  |  1 files  |  6ms
target : ...\dsh-code-quarantine\demo
engine : ast=- | lexical-only=html

VERDICT: SAFE   CRITICAL 0 | WARNING 0 | INFO 0

未发现问题。
```

整页写着「推荐访问」「购买套餐 / 充值：发卡网购买链接」和一串外链，判定是「未发现问题」。

## 根因：HTML 的词法层没有 span

问题不在规则，在 `scripts/qcore/lexer.py`。

`_scan_markup()` 原本只做一件事：

```python
while i < n:
    if text.startswith("<!--", i):
        ...  # 标成 comment
```

也就是说，HTML 文件里只有 `<!-- -->` 会被标记。**属性值和文本节点既不是 comment
也不是 string**，全部落在 `region() == "code"` 上。

而广告规则拿数据的方式是 `_aux_text_by_line(source)`——只收
`comment` / `docstring` / `string` 三种 span 的逐行文本。HTML 的 span 集合为空，
逐行文本缓存就是空的，AD001 的「话术窗口」永远扫不到东西。

更糟的是 `region() == "code"` 让 AD002 走「代码字符串里的硬编码外链」分支——
可那条分支也只在 `region == "string"` 时进入。于是两条规则同时沉默。

这不是「规则写错了」，是**「这门语言没有数据」**。用别的语言写同样的内容立刻能报：

```bash
# 同样的文案，换成 .py 文件
python scripts/quarantine.py .chk/a.py --full --no-color
```
```
VERDICT: REVIEW   CRITICAL 0 | WARNING 4 | INFO 0
  AD001  a.py:3:20  推广话术「购买」与外链共现: qm.qq.com
  AD001  a.py:4:23  推广话术「购买」与外链共现: catfk.com
  AD001  a.py:5:15  推广话术「购买」与外链共现: d1api.xin
  AD002  a.py:8:13  代码字符串中的硬编码外链未被网络/链接 API 使用: d1api.xin
```

## 修复：让 markup 拥有真正的 span

`_scan_markup()` 重写为三件事：

| 区域 | span 类型 | 理由 |
| --- | --- | --- |
| `<!-- -->` | `comment` | 注释掉的标签不是真实加载 |
| 引号内的属性值 | `string` | `href="https://..."` 是 HTML 里「数据」的主要载体 |
| 标签之间的文本节点 | `string` | 页面正文就是推广话术的所在地 |
| `<script>` / `<style>` / `<textarea>` 的块体 | 保持 `code` | 里面的 JS/CSS 是代码，要交给 JS 与 shell 规则 |

配套两个细节：

- `_skip_tag()` 逐字符找 `>`，跳过引号内的内容。属性值里出现 `>`（`?a=1>2`）
  时，用 `text.find(">")` 会把标签切一半，剩下的值变成文本节点。
- 闭合标签（`</style>`）**不能**走「跳过块体」分支。首版漏了这个判断，
  `</style>` 会去找它自己之后的 `</style>`，找不到就把整篇文档当成一段 raw text——
  页面后半部分全部漏检（实测 span 数从 168 掉到 11）。

## 修复后

```bash
python scripts/quarantine.py demo/d1api-home.html --full --no-color
```
```
VERDICT: REVIEW   CRITICAL 0 | WARNING 8 | INFO 0

  AD002  d1api-home.html:95:16   ...d1api.xin
  AD001  d1api-home.html:113:77  推广话术「购买」与外链共现: qm.qq.com
  AD001  d1api-home.html:114:81  推广话术「购买」与外链共现: catfk.com
  AD001  d1api-home.html:115:76  推广话术「购买」与外链共现: www.kdocs.cn
  AD002  d1api-home.html:122:68  ...d1api.xin
  AD002  d1api-home.html:131:47  ...d1api.xin
  AD001  d1api-home.html:155:6   推广话术「购买」与外链共现: d1api.xin
  AD002  d1api-home.html:167:16  ...d1api.xin
```

逐条核对：

| # | 行 | 规则 | 命中内容 | 判对了吗 |
| --- | --- | --- | --- | --- |
| 1 | 95 | AD002 | 说明文字里的 `https://d1api.xin/` | ✅ 确实是非功能性外链 |
| 2 | 113 | AD001 | 「购买」+ `qm.qq.com` | ✅ 售后群引流 |
| 3 | 114 | AD001 | 「购买」+ `catfk.com` | ✅ 发卡网购买 |
| 4 | 115 | AD001 | 「购买」+ `www.kdocs.cn` | ✅ 教程引流（话术窗口 3 行内） |
| 5 | 122 | AD002 | 「接口地址：`https://d1api.xin/v1`」 | ✅ 硬编码 base URL |
| 6 | 131 | AD002 | 代码块标题里的来源 URL | ✅ 同上 |
| 7 | 155 | AD001 | 代码块内「购买套餐 / 充值」+ `d1api.xin` | ✅ 话术窗口跨越了代码块边界 |
| 8 | 167 | AD002 | 页脚「复刻来源」 | ✅ 同上 |

**没有一条是误报**，也**没有该报的漏掉**。AD005 正确地保持沉默——页面没有外链
`<script src>` / `<iframe src>`。

（上表的行号在 CSS 补丁后会偏移几行，规则与命中内容不变。）

### 页面本身的两处排版修正

复刻页在窄屏下有 2px 横向溢出（375px 视口下 `scrollWidth = 377`）。越界元素是
三行 `.row` 里的 `<span>`：里面放的是完整 URL（`https://qm.qq.com/q/sf0IHvBE8a`
这类），URL 没有可断行的空格，而 flex 默认 `nowrap`。修法是 `.row` 加
`flex-wrap: wrap`、`> span` 加 `min-width: 0; overflow-wrap: anywhere`。
代码块里的 `<code>` 保持 `white-space: pre`——那 299 个字符要逐行还原原始页面，
折行会破坏对照；横向滚动交给外层的 `<pre>`，不撑宽页面。
修后 320 / 360 / 375 / 420 / 768 / 1024 / 1440 七个宽度全部 `scrollWidth == clientWidth`。

## 顺带暴露的第二个缺口：AD005 没有豁免测试路径

给这个页面写回归用例时，闸门拒绝了写入：

```
[dsh-code-quarantine] BLOCK  CRITICAL 2 | WARNING 3
- CRITICAL tests/test_quarantine.py:37 [AD005] 引入未受信外部资源: evil-host-zzz.net
- CRITICAL tests/test_quarantine.py:43 [AD005] 引入未受信外部资源: relay-promo-hub.top
```

AD001 / AD002 / AD004 都写了 `not is_test`（夹具里必须存在恶意样本，否则测不了），
**AD005 漏了同一条豁免**。后果是：给规则写回归用例时，检测工具被自己的夹具锁死——
agent 无法写入那条「证明规则有效」的测试。

修复：`ad.py` 的 AD005 分支补 `and not is_test`，与另外三条规则对齐。
`in_test_path` 只匹配 `tests/` `fixtures/` `test_*.py` 等路径，真实页面不受影响。

## 回归

| 套件 | 结果 |
| --- | --- |
| `python -m unittest discover -s tests` | **Ran 153 tests, OK**（新增 13 个 markup 用例） |
| `python tests/brutal_suite.py` | **100/100 通过** |
| `python tests/idea_matrix.py` | **83/83 PASS** |
| `python tests/realworld_regression.py` | **CRITICAL 0 / WARNING 36 / INFO 105**（8 库 581 文件，无回归） |
| `node dsh-plugin/test-gate.mjs` | 23/23 |
| `node dsh-plugin/test-state.mjs` | 62/62 |
| `node dsh-plugin/test-client.mjs` | 17/17 |
| 仓库自扫描 | `VERDICT: SAFE CRITICAL 0 | WARNING 0 | INFO 0`（56 files） |

新增的 13 个用例分两组：

- `LexerContract` 里 6 个：属性值与文本节点是 string、注释仍是 comment、
  闭合标签不吞后文、`<script>` 体内是 code、属性里的 `>` 不切标签。
- `MarkupDetection` 里 7 个：话术 + 链接（文本节点 / 属性 / 纯文本三种位置）、
  外链 `<script>` 是 CRITICAL、外链 `<iframe>` 是 CRITICAL、无话术页面保持干净、
  复刻页本身必须非 SAFE、测试路径豁免 AD005。

其中「复刻页本身必须非 SAFE」这一条**刻意用 `use_ignore=False` 的配置**：
仓库的 `.dsh-quarantine-ignore` 为了不让整仓自扫描被自己的夹具染红，登记了
`AD001 demo/**` 等三条；而单测的 `Config` 根在仓库根，会把这三条一起读进来。
用它去扫复刻页，测到的其实是「豁免文件写对没有」，夹具真的坏了也照样绿。
命令行那条 `python scripts/quarantine.py demo/d1api-home.html` 不受影响——
目标目录是 `demo/`，项目根随之变成 `demo/`，仓库根的豁免文件根本不参与。

## 怎么复现

```bash
# 直接扫复刻页（应当 REVIEW，8 条 WARNING）
python scripts/quarantine.py demo/d1api-home.html --full --no-color

# 显式绕开本仓库的豁免，确认这 8 条确实来自页面内容而非豁免策略
python scripts/quarantine.py demo/d1api-home.html --full --no-color --no-ignore

# 只看 markup 相关的词法与规则行为
cd tests && python -m unittest test_quarantine.LexerContract test_quarantine.MarkupDetection -v

# 整仓自扫描（应当 SAFE——夹具已在 .dsh-quarantine-ignore 里登记）
python scripts/quarantine.py . --full --no-color
```

用浏览器打开 `demo/d1api-home.html` 可以直接看到复刻效果；页面顶部有醒目提示
说明它是检测夹具而非真实站点，所有链接都指向原始站点，不要在任何地方输入密钥。
