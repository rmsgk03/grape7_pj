from __future__ import annotations

import gradio as gr

from scanner.ml_model import predict_code
from scanner.rules import analyze_code


DEFAULT_CODE = """import os
import sqlite3

conn = sqlite3.connect("app.db")
cursor = conn.cursor()

user_id = input("user id: ")
cursor.execute("SELECT * FROM users WHERE id = " + user_id)

filename = input("file name: ")
open(filename).read()

cmd = "ping " + user_id
os.system(cmd)
"""

LABEL_KO = {
    "SAFE": "안전 코드",
    "SQL_INJECTION": "SQL Injection",
    "COMMAND_INJECTION": "Command Injection",
    "PATH_TRAVERSAL": "Path Traversal",
    "BUFFER_OVERFLOW": "Buffer Overflow",
    "XSS": "XSS",
    "UNCERTAIN": "판단 보류",
}

SEVERITY_KO = {
    "critical": "매우 높음",
    "high": "높음",
    "medium": "보통",
    "low": "낮음",
    "info": "정보",
}


def analyze(source_code: str) -> tuple[str, str]:
    if not source_code.strip():
        message = "코드를 입력한 뒤 Analyze 버튼을 눌러 주세요."
        return message, message

    findings = analyze_code(source_code)
    ai_result = predict_code(source_code)

    return render_rule_findings(findings), render_ai_result(ai_result)


def render_rule_findings(findings) -> str:
    if not findings:
        return "### 규칙 기반 분석 결과\n\n명확하게 탐지된 취약점 후보가 없습니다."

    lines = ["### 규칙 기반 분석 결과"]
    for index, finding in enumerate(findings, 1):
        severity = SEVERITY_KO.get(finding.severity, finding.severity)
        lines.extend(
            [
                "",
                f"#### {index}. {finding.vulnerability} / 위험도: {severity}",
                f"- 위치: `{finding.line}`번째 줄",
                f"- 탐지 규칙: `{finding.rule_id}`",
                f"- 취약한 이유: {finding.reason}",
                f"- 개선 방법: {finding.recommendation}",
                "",
                "```python",
                finding.code or "# 코드 위치를 추출하지 못했습니다.",
                "```",
            ]
        )
    return "\n".join(lines)


def render_ai_result(ai_result) -> str:
    if ai_result.status != "ok":
        return "\n".join(
            [
                "### AI 보조 분석",
                "",
                "**AI 모델을 불러오지 못했습니다.**",
                "",
                f"- 오류: {ai_result.error}",
                f"- 모델 경로: `{ai_result.model_path}`",
            ]
        )

    confidence = float(ai_result.confidence or 0)
    confidence_percent = confidence * 100
    threshold_percent = float(ai_result.confidence_threshold) * 100
    raw_label = str(ai_result.raw_prediction or "-")
    raw_label_ko = LABEL_KO.get(raw_label, raw_label.replace("_", " ").title())

    if ai_result.prediction == "UNCERTAIN":
        title = "판단 보류"
        summary = (
            "AI 모델의 확신도가 낮아서 취약점 유형을 확정하지 않았습니다. "
            "이 경우에는 왼쪽의 규칙 기반 탐지 결과를 우선 확인하는 것이 좋습니다."
        )
        risk_note = "AI 단독 판단은 보류되었습니다."
        next_action = "규칙 기반 결과가 있다면 해당 위치를 먼저 수정하고, 없다면 사람이 추가 검토하세요."
    elif ai_result.prediction == "SAFE":
        title = "안전 코드에 가까움"
        summary = "AI 모델은 이 코드가 학습된 안전 코드 예시와 가장 비슷하다고 판단했습니다."
        risk_note = "AI 기준 위험 가능성은 낮지만, 최종 안전 판정은 아닙니다."
        next_action = "규칙 기반 탐지 결과가 없는지 함께 확인하세요."
    else:
        label = LABEL_KO.get(str(ai_result.prediction), str(ai_result.prediction).replace("_", " ").title())
        title = f"{label} 의심"
        summary = f"AI 모델은 이 코드가 `{label}` 취약 패턴과 유사하다고 판단했습니다."
        risk_note = "취약 가능성이 있으므로 보안 검토가 필요합니다."
        next_action = "왼쪽 규칙 기반 결과와 함께 의심 위치를 확인하고, 입력값 검증과 안전한 API 사용 여부를 점검하세요."

    top_lines = []
    for item in ai_result.top_predictions or []:
        label = str(item["label"])
        label_ko = LABEL_KO.get(label, label.replace("_", " ").title())
        top_lines.append(f"- **{label_ko}**: {float(item['confidence']) * 100:.1f}%")

    return "\n".join(
        [
            "### AI 보조 분석",
            "",
            f"## {title}",
            "",
            summary,
            "",
            "#### 신뢰도",
            f"- AI 확신도: **{confidence_percent:.1f}%**",
            f"- 판단 기준: **{threshold_percent:.0f}% 이상**",
            f"- 모델이 가장 가깝게 본 라벨: **{raw_label_ko}**",
            "",
            "#### 해석",
            f"- {risk_note}",
            f"- 다음 행동: {next_action}",
            "",
            "> AI 결과는 최종 판정이 아니라 보조 판단입니다. 규칙 기반 분석 결과와 함께 확인하세요.",
            "",
            "#### AI 후보 라벨",
            *top_lines,
        ]
    )


with gr.Blocks(title="AI Vulnerability Scanner") as demo:
    gr.Markdown(
        """
        # AI Vulnerability Scanner

        Python 코드를 입력하면 규칙 기반 탐지 결과와 CodeBERT 기반 AI 보조 분석을 함께 보여줍니다.
        AI 결과는 최종 판정이 아니라 보안 검토를 돕는 참고 정보입니다.
        """
    )

    code_input = gr.Code(
        label="분석할 Python 코드",
        value=DEFAULT_CODE,
        language="python",
        lines=18,
    )
    analyze_button = gr.Button("Analyze", variant="primary")

    with gr.Row():
        rule_output = gr.Markdown(label="규칙 기반 분석 결과")
        ai_output = gr.Markdown(label="AI 보조 분석")

    analyze_button.click(
        fn=analyze,
        inputs=code_input,
        outputs=[rule_output, ai_output],
    )


if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=7860, show_error=True)
