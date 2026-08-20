"""Render promoted business JSON to deterministic Markdown."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Callable


def _header(value: dict[str, Any], title: str) -> list[str]:
    return [
        f"# {title}",
        "",
        f"- 运行：{value['run_id']}",
        f"- 业务日期：{value['business_date']}",
        f"- 状态：{value['status']}",
        "",
        str(value.get("summary") or value.get("executive_summary") or ""),
        "",
    ]


def render_inspector(value: dict[str, Any]) -> str:
    lines = _header(value, "异常巡检")
    lines.extend(["## 三维健康", ""])
    for item in value["dimension_summary"]:
        lines.append(
            f"- {item['dimension']}：{item['score']} / {item['status']}；"
            f"{item['assessment']}"
        )
    lines.extend(["", "## 调查 Case", ""])
    for case in value["cases"]:
        lines.extend(
            [
                f"### {case['case_id']} · {case['title']}",
                "",
                f"- 异常：{', '.join(case['anomaly_ids'])}",
                f"- 调查价值：{'是' if case['investigation_worthy'] else '否'}",
                f"- 证据：{', '.join(case['evidence_refs'])}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def render_diagnosis(value: dict[str, Any]) -> str:
    lines = _header(value, "诊断结论")
    for item in value["diagnoses"]:
        lines.extend(
            [
                f"## {item['diagnosis_id']} · {item['case_id']}",
                "",
                f"- 异常：{', '.join(item['anomaly_ids'])}",
                f"- 结论：{item['conclusion_summary']}",
                f"- 最可信解释：{item['root_cause']}",
                f"- 置信度：{item['confidence']:.0%}",
                f"- 证据：{', '.join(item['evidence_refs'])}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def render_actions(value: dict[str, Any]) -> str:
    lines = _header(value, "建议方案")
    for item in value["actions"]:
        lines.extend(
            [
                f"## {item['action_id']} · {item['title']}",
                "",
                f"- 类型：{item['action_type']}",
                f"- 责任人：{item['owner']}",
                f"- 目标指标：{', '.join(item['target_metric_ids'])}",
                f"- 内容：{item['description']}",
            ]
        )
        if item["action_type"] == "manual_adjustment":
            lines.append(f"- 人工调整：{item['adjustment_content']}")
        lines.extend(
            [
                "- 验收：",
                *[f"  - {criterion}" for criterion in item["acceptance_criteria"]],
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def render_audit(value: dict[str, Any]) -> str:
    lines = _header(value, "审核结果")
    for item in value["logic_reviews"]:
        lines.extend(
            [
                f"## {item['review_id']} · {item['action_id']}",
                "",
                f"- 结论：{item['verdict']}",
                f"- ID 闭合：{item['id_closure']}",
                f"- 因果边界：{item['causality_assessment']}",
                f"- 理由：{item['rationale']}",
                "",
            ]
        )
    if value["effect_reviews"]:
        lines.extend(["## 到期异常回看", ""])
        for item in value["effect_reviews"]:
            lines.append(
                f"- {item['review_key']}：{item['conclusion']}；"
                f"{item['attribution_limit']}"
            )
    return "\n".join(lines).rstrip() + "\n"


def render_report(value: dict[str, Any]) -> str:
    lines = [
        f"# {value['headline']}",
        "",
        f"- 运行：{value['run_id']}",
        f"- 业务日期：{value['business_date']}",
        f"- 健康分：{value['health_score']}",
        f"- 健康区间：{value['health_assessment']['band']}",
        "",
        value["executive_summary"],
        "",
        "## 管理优先级",
        "",
    ]
    for item in value["management_priorities"]:
        lines.extend(
            [
                f"{item['rank']}. **{item['title']}**",
                f"   - 责任人：{item['owner']}",
                f"   - 原因：{item['why_now']}",
                f"   - 待决策：{item['decision_needed']}",
            ]
        )
    lines.extend(["", "## 正式建议", ""])
    for item in value["recommended_actions"]:
        lines.extend(
            [
                f"- {item['action_id']} · {item['title']} "
                f"（{item['audit_verdict']}）",
                f"  - 类型：{item['action_type']}",
                f"  - 责任人：{item['owner']}",
                f"  - 指标：{', '.join(item['target_metric_ids'])}",
            ]
        )
    if value["effect_reviews"]:
        lines.extend(["", "## 到期回看", ""])
        for item in value["effect_reviews"]:
            lines.append(f"- {item['review_key']}：{item['conclusion']}")
    lines.extend(
        [
            "",
            "## 决策瓶颈",
            "",
            value["decision_bottleneck"],
            "",
            "> 投递请求仅由服务器在完成态封存并核验清单后执行；"
            "Dolphin Agent 不持有通知凭据或投递能力。",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


RENDERERS: dict[str, Callable[[dict[str, Any]], str]] = {
    "inspector": render_inspector,
    "diagnostician": render_diagnosis,
    "advisor": render_actions,
    "auditor": render_audit,
    "reporter": render_report,
}


def render(stage: str, value: dict[str, Any]) -> str:
    try:
        renderer = RENDERERS[stage]
    except KeyError as exc:
        raise ValueError(f"unsupported Stage: {stage}") from exc
    return renderer(value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=sorted(RENDERERS), required=True)
    args = parser.parse_args()
    value = json.load(sys.stdin)
    if not isinstance(value, dict):
        raise SystemExit("document must be a JSON object")
    sys.stdout.write(render(args.stage, value))


if __name__ == "__main__":
    main()
