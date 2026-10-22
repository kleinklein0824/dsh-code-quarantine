# HTML 标记检测回归记录

这份记录说明 HTML 页面中的推广话术和外链为什么能被规则识别。所有示例均为
合成内容，统一使用虚构域名 `relay-promo-hub.top`，不包含真实站点、邀请码、
支付链接或联系方式。

## 合成样本

回归测试在 `tests/test_quarantine.py` 的 `MarkupDetection` 中直接构造 HTML：

```html
<h1>AI API</h1>
<p>推荐访问 <a href="https://relay-promo-hub.top/doc">获取最新文档</a></p>
<a href="https://relay-promo-hub.top/buy">购买套餐</a>
```

这种页面同时包含：

1. 推广话术与外链共现；
2. 属性值和文本节点中的硬编码链接；
3. 不应产生误报的普通 HTML 文本。

## 曾经的漏检

早期 `lexer._scan_markup` 只把 `<!-- -->` 标为注释。HTML 属性值和标签之间的
文本节点既不是 `comment` 也不是 `string`，导致广告规则拿到的逐行文本缓存
为空。推广话术明明写在页面上，扫描结果却可能是 `SAFE 0/0/0`。

修复后：

| 区域 | span 类型 | 用途 |
| --- | --- | --- |
| `<!-- -->` | `comment` | 区分注释 |
| 引号内的属性值 | `string` | 识别 `href`、`src` 等链接 |
| 标签之间的文本节点 | `string` | 识别页面正文里的话术 |
| `<script>`、`<style>`、`<textarea>` 块体 | `code` | 交给 JS 与 shell 规则 |

标签解析还需要跳过引号内的 `>`，并正确处理闭合标签，避免把后续正文误判为
原始文本。相关断言覆盖属性值、文本节点、注释、外部脚本和外部 iframe。

## 复现

```bash
python -m unittest tests.test_quarantine.MarkupDetection -v
```

真实站点复刻页已从发布包移除，回归测试只使用运行时构造的合成样本。
