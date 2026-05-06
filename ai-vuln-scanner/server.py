from __future__ import annotations

import os
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from scanner import analyze_code, init_db, load_recent_scans, load_stats, save_scan


HOST = "127.0.0.1"
PORT = int(os.environ.get("PORT", "8501"))

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


class AppHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self._send_page(DEFAULT_CODE, [])

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8")
        form = parse_qs(raw_body)
        source_code = form.get("source_code", [""])[0]
        findings = analyze_code(source_code)
        save_scan(source_code, findings)
        self._send_page(source_code, findings)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_page(self, source_code: str, findings) -> None:
        init_db()
        html = render_page(source_code, findings)
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def render_page(source_code: str, findings) -> str:
    result_html = render_findings(findings)
    stats_html = render_stats()
    return f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>웹 기반 취약점 분석 MVP</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --surface: #ffffff;
      --line: #d9dee7;
      --text: #17202a;
      --muted: #5c6978;
      --accent: #116149;
      --danger: #b42318;
      --warning: #9a6700;
      --info: #175cd3;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Arial, "Malgun Gothic", sans-serif;
    }}
    header {{
      background: var(--surface);
      border-bottom: 1px solid var(--line);
      padding: 24px 32px 18px;
    }}
    main {{
      display: grid;
      grid-template-columns: minmax(0, 1.2fr) minmax(320px, 0.8fr);
      gap: 20px;
      padding: 24px 32px 40px;
    }}
    h1 {{ margin: 0 0 8px; font-size: 28px; }}
    h2 {{ margin: 0 0 14px; font-size: 18px; }}
    p {{ margin: 0; color: var(--muted); line-height: 1.5; }}
    section, article {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
    }}
    textarea {{
      width: 100%;
      min-height: 430px;
      resize: vertical;
      border: 1px solid #b9c1cd;
      border-radius: 6px;
      padding: 14px;
      font: 14px/1.5 Consolas, "Courier New", monospace;
      color: var(--text);
    }}
    button {{
      margin-top: 12px;
      border: 0;
      border-radius: 6px;
      background: var(--accent);
      color: white;
      padding: 11px 18px;
      font-weight: 700;
      cursor: pointer;
    }}
    .stack {{ display: grid; gap: 14px; }}
    .finding {{
      border: 1px solid var(--line);
      border-left: 5px solid var(--danger);
      border-radius: 8px;
      padding: 14px;
      background: #fff;
    }}
    .finding.medium {{ border-left-color: var(--warning); }}
    .finding.info {{ border-left-color: var(--info); }}
    .finding h3 {{ margin: 0 0 8px; font-size: 16px; }}
    .meta {{ color: var(--muted); font-size: 13px; margin-bottom: 8px; }}
    pre {{
      overflow-x: auto;
      background: #f0f3f7;
      border-radius: 6px;
      padding: 10px;
      font-size: 13px;
    }}
    .bar {{
      display: grid;
      grid-template-columns: 140px 1fr 42px;
      gap: 10px;
      align-items: center;
      margin: 10px 0;
      font-size: 14px;
    }}
    .track {{ height: 12px; background: #e6eaf0; border-radius: 999px; overflow: hidden; }}
    .fill {{ height: 100%; background: var(--accent); }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 9px 6px; text-align: left; }}
    th {{ color: var(--muted); font-size: 13px; }}
    @media (max-width: 900px) {{
      main {{ grid-template-columns: 1fr; padding: 18px; }}
      header {{ padding: 20px 18px; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>웹 기반 취약점 분석 프로그램</h1>
    <p>MVP: SQL Injection, Command Injection, Path Traversal을 먼저 분석합니다.</p>
  </header>
  <main>
    <section>
      <h2>코드 입력</h2>
      <form method="post">
        <textarea name="source_code" spellcheck="false">{escape(source_code)}</textarea>
        <button type="submit">분석하기</button>
      </form>
    </section>
    <div class="stack">
      <article>
        <h2>분석 결과</h2>
        {result_html}
      </article>
      <article>
        <h2>누적 통계</h2>
        {stats_html}
      </article>
    </div>
  </main>
</body>
</html>"""


def render_findings(findings) -> str:
    if findings is None:
        findings = []
    if not findings:
        return "<p>아직 분석 결과가 없거나, 탐지된 취약점 후보가 없습니다.</p>"

    cards = []
    for finding in findings:
        severity_class = "medium" if finding.severity == "medium" else "info" if finding.severity == "info" else ""
        cards.append(
            f"""
            <div class="finding {severity_class}">
              <h3>{escape(finding.vulnerability)} · {escape(finding.severity.upper())}</h3>
              <div class="meta">라인 {finding.line} · {escape(finding.rule_id)}</div>
              <pre><code>{escape(finding.code or "(코드 위치를 추출하지 못했습니다.)")}</code></pre>
              <p><strong>이유</strong>: {escape(finding.reason)}</p>
              <p><strong>개선 방법</strong>: {escape(finding.recommendation)}</p>
            </div>
            """
        )
    return "\n".join(cards)


def render_stats() -> str:
    stats = load_stats()
    recent = load_recent_scans()
    pieces = []

    if stats:
        max_count = max(item["count"] for item in stats)
        for item in stats:
            width = int((item["count"] / max_count) * 100)
            pieces.append(
                f"""
                <div class="bar">
                  <span>{escape(str(item["vulnerability"]))}</span>
                  <div class="track"><div class="fill" style="width:{width}%"></div></div>
                  <strong>{item["count"]}</strong>
                </div>
                """
            )
    else:
        pieces.append("<p>아직 저장된 분석 결과가 없습니다.</p>")

    if recent:
        rows = "\n".join(
            f"<tr><td>{escape(str(row['created_at']))}</td><td>{row['finding_count']}</td><td>{escape(str(row['vulnerabilities']))}</td></tr>"
            for row in recent
        )
        pieces.append(
            f"""
            <h2 style="margin-top:18px">최근 분석 기록</h2>
            <table>
              <thead><tr><th>시간</th><th>탐지 수</th><th>유형</th></tr></thead>
              <tbody>{rows}</tbody>
            </table>
            """
        )

    return "\n".join(pieces)


def main() -> None:
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), AppHandler)
    print(f"Open http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
