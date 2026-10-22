#!/usr/bin/env python3
"""dsh-code-quarantine CLI.

Two entry modes, one rule engine:

  full / incremental / since   -> audit a directory (CI gate, end-of-task sweep)
  stdin                        -> scan a single buffer (pre-write gate / hook)

Exit codes: 0 SAFE (or below the --fail-on threshold), 1 REVIEW, 2 BLOCK.
"""

from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_ROOT = os.path.dirname(HERE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from qcore import cache, llm, report  # noqa: E402
from qcore.config import Config  # noqa: E402
from qcore.rules import arch  # noqa: E402
from qcore.scan import ScanOptions, collect_sources, run_scan, scan_text  # noqa: E402

DEFAULT_RULES = os.path.join(SKILL_ROOT, "rules")


def _llm_check(cfg) -> int:
    info = cfg.public()
    print("AI 复核配置：")
    for key in ("provider", "base_url", "model", "has_key", "key_hint", "source", "host_model"):
        print("  %-11s %s" % (key, info.get(key)))
    if not cfg.ready:
        print("\n未配置完整：需要 base_url + model + api_key。")
        print("  export DSH_QUARANTINE_LLM_API_KEY=...")
        print("  export DSH_QUARANTINE_LLM_BASE_URL=https://api.openai.com/v1")
        print("  export DSH_QUARANTINE_LLM_MODEL=<模型名>")
        return 2
    try:
        reply = llm.chat(cfg, "只回复两个字：可用")
    except Exception as exc:
        print("\n连通性测试失败：%s" % exc)
        return 1
    print("\n连通性测试通过，模型回复：%s" % (reply or "").strip()[:80])
    return 0


def _ensure_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dsh-code-quarantine",
        description="检查 AI 生成 / 中转站返回的代码是否存在广告注入、供应链投毒与架构偏离。",
    )
    parser.add_argument("target", nargs="?", default=".", help="扫描目标目录（默认当前目录）")

    mode = parser.add_argument_group("扫描模式")
    mode.add_argument("--full", action="store_true", help="全量逐文件扫描（默认）")
    mode.add_argument("--incremental", action="store_true", help="仅检查 git 变更文件")
    mode.add_argument("--since", metavar="REF", help="从指定 commit 起检查")
    mode.add_argument("--files", nargs="+", metavar="PATH", help="仅检查指定文件")
    mode.add_argument("--stdin", action="store_true", help="从标准输入读取单个片段")
    mode.add_argument("--path", metavar="NAME", help="配合 --stdin 指定逻辑文件名（用于识别语言）")

    out = parser.add_argument_group("输出")
    out.add_argument("--format", default="text", choices=["text", "json", "md", "markdown", "sarif"])
    out.add_argument("--out", metavar="FILE", help="写入文件而不是标准输出")
    out.add_argument("--no-color", action="store_true")
    out.add_argument("--quiet", action="store_true", help="仅在发现问题时输出摘要")
    out.add_argument("--fail-on", default="critical", choices=["none", "warning", "critical"],
                     help="CI 失败阈值（默认 critical）")

    cfg_group = parser.add_argument_group("配置")
    cfg_group.add_argument("--rules", default=DEFAULT_RULES, help="规则目录")
    cfg_group.add_argument("--config", help="项目配置 .dsh-quarantine.yml")
    cfg_group.add_argument("--ignore", help="豁免文件 .dsh-quarantine-ignore")
    cfg_group.add_argument("--no-ignore", action="store_true")
    cfg_group.add_argument("--include-tests", action="store_true", help="同时扫描测试目录")
    cfg_group.add_argument("--max-file-size", type=int, default=512, metavar="KB")
    cfg_group.add_argument("--batch", type=int, default=40, metavar="N", help="每批文件数")

    base = parser.add_argument_group("基线")
    base.add_argument("--baseline", metavar="FILE", help="签名基线文件")
    base.add_argument("--write-baseline", metavar="FILE", help="生成签名基线后退出")

    ai = parser.add_argument_group("AI 复核")
    ai.add_argument("--llm", action="store_true", help="强制启用 AI 复核（即使未完整配置，也会说明缺什么）")
    ai.add_argument("--no-llm", action="store_true", help="禁用 AI 复核，只用规则")
    ai.add_argument("--llm-deep", action="store_true", help="对没有规则命中的文件也做一次语义复核（更贵）")
    ai.add_argument("--llm-model", metavar="NAME", help="覆盖模型名（默认取对话模型 / 环境变量）")
    ai.add_argument("--llm-base", metavar="URL", help="覆盖 API base，如 https://api.openai.com/v1")
    ai.add_argument("--llm-provider", choices=["openai", "anthropic"], help="接口协议")
    ai.add_argument("--llm-key-env", metavar="VAR", help="从哪个环境变量读密钥")
    ai.add_argument("--llm-check", action="store_true", help="只测试 AI 连通性后退出")

    info = parser.add_argument_group("信息")
    info.add_argument("--list-rules", action="store_true")
    info.add_argument("--explain", metavar="RULE_ID")
    return parser


def _print_rules(cfg: Config) -> None:
    print("规则清单（%d 条）" % len(cfg.rules))
    for rid in sorted(cfg.rules):
        rule = cfg.rules[rid]
        flag = "on " if rule.get("enabled", True) else "off"
        print("  %-6s %s %-9s %-22s %s" % (
            rid, flag, rule["severity"], rule["category"], rule.get("title", "")))
    if cfg.warnings:
        print("\n配置告警:")
        for warning in cfg.warnings:
            print("  - %s" % warning)


def _print_rule(cfg: Config, rule_id: str) -> int:
    rule = cfg.rules.get(rule_id.upper())
    if not rule:
        print("未找到规则: %s" % rule_id, file=sys.stderr)
        return 3
    print("%s  %s" % (rule_id.upper(), rule.get("title", "")))
    print("  severity : %s" % rule["severity"])
    print("  category : %s" % rule["category"])
    print("  enabled  : %s" % rule.get("enabled", True))
    print("  message  : %s" % rule.get("message", ""))
    print("  fix      : %s" % rule.get("suggestion", ""))
    data = rule.get("data") or {}
    if data:
        print("  data     :")
        for key, value in data.items():
            print("    %-20s %s" % (key, value))
    return 0


def main(argv=None) -> int:
    _ensure_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.stdin:
        text = sys.stdin.read()
        rel = args.path or "stdin.txt"
        cfg = Config(args.rules, os.path.dirname(os.path.abspath(rel)) or ".",
                     config_file=args.config, ignore_file=args.ignore, use_ignore=not args.no_ignore)
        result = scan_text(text, rel, cfg)
        output = report.render(result, args.format, color=False)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(output + "\n")
        else:
            print(output)
        if args.fail_on == "none":
            return 0
        if result.verdict() == "BLOCK":
            return 2
        if result.verdict() == "REVIEW" and args.fail_on == "warning":
            return 1
        return 0

    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        print("目标不存在: %s" % target, file=sys.stderr)
        return 3
    root = target if os.path.isdir(target) else os.path.dirname(target)

    cfg = Config(args.rules, root, config_file=args.config, ignore_file=args.ignore,
                 use_ignore=not args.no_ignore)

    if args.list_rules:
        _print_rules(cfg)
        return 0
    if args.explain:
        return _print_rule(cfg, args.explain)

    mode = "full"
    if args.incremental:
        mode = "incremental"
    elif args.since:
        mode = "since"
    elif args.files:
        mode = "files"

    baseline_path = args.baseline or os.path.join(
        root, str((cfg.data("AR004") or {}).get("baseline_file") or ".dsh-quarantine-baseline.json")
    )

    if args.write_baseline:
        opts = ScanOptions(mode="full", include_tests=args.include_tests,
                           max_file_size=max(1, args.max_file_size) * 1024,
                           write_state=False)
        sources = collect_sources(root, cfg, opts)
        data = arch.build_baseline(sources)
        arch.save_baseline(args.write_baseline, data)
        print("基线已写入 %s（%d 个文件）" % (args.write_baseline, len(data.get("files") or {})))
        return 0

    baseline = arch.load_baseline(baseline_path)

    llm_cfg = llm.resolve(cfg.project_data)
    if args.llm_model:
        llm_cfg.model = args.llm_model
    if args.llm_base:
        llm_cfg.base_url = args.llm_base.rstrip("/")
    if args.llm_provider:
        llm_cfg.provider = args.llm_provider
    if args.llm_key_env:
        llm_cfg.api_key = os.environ.get(args.llm_key_env, "")
        llm_cfg.source = "env:" + args.llm_key_env

    if args.llm_check:
        return _llm_check(llm_cfg)

    use_llm = None
    if args.no_llm:
        use_llm = None
    elif args.llm:
        use_llm = llm_cfg
    elif llm_cfg.ready and llm_cfg.source in ("env", "openai-env", "anthropic-env"):
        # 只有"你自己环境变量里的配置"才自动启用
        use_llm = llm_cfg
    elif llm_cfg.ready and llm_cfg.source == "project":
        # 项目配置可能随仓库一起来，端点可能是别人的服务器：
        # 自动发送代码等于把源码外传，必须显式确认
        if os.environ.get("DSH_QUARANTINE_LLM_TRUST_PROJECT") == "1":
            use_llm = llm_cfg
        else:
            print(
                "注意：项目配置里指定了 AI 端点（%s），未自动启用。\n"
                "      克隆来的仓库可能借此把源码发到第三方；确认可信后加 --llm，"
                "或设置 DSH_QUARANTINE_LLM_TRUST_PROJECT=1。"
                % (llm_cfg.base_url or "?"),
                file=sys.stderr,
            )

    opts = ScanOptions(
        mode=mode,
        files=args.files or [],
        since=args.since,
        include_tests=args.include_tests,
        max_file_size=max(1, args.max_file_size) * 1024,
        batch_size=args.batch,
        baseline=baseline,
        llm=use_llm,
        llm_deep=args.llm_deep,
    )
    result = run_scan(root, cfg, opts)
    cache.save_summary(root, result)

    color = not args.no_color and sys.stdout.isatty() and args.format == "text"
    output = report.render(result, args.format, color=color)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
        if args.quiet:
            counts = result.counts()
            print("%s  CRITICAL %d | WARNING %d | INFO %d" % (
                result.verdict(), counts["CRITICAL"], counts["WARNING"], counts["INFO"]))
    elif not (args.quiet and not result.findings):
        print(output)

    if cfg.warnings and not args.quiet:
        print("\n配置告警:", file=sys.stderr)
        for warning in cfg.warnings:
            print("  - %s" % warning, file=sys.stderr)

    if result.error:
        # 扫描本身失败（坏 ref / 读不到规则）：不能用 --fail-on none 掩盖
        return 3
    if args.fail_on == "none":
        return 0
    if result.verdict() == "BLOCK":
        return 2
    if result.verdict() == "REVIEW" and args.fail_on == "warning":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
