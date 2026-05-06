from __future__ import annotations

import pandas as pd
import streamlit as st

from scanner import analyze_code, init_db, load_recent_scans, load_stats, save_scan


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


def main() -> None:
    st.set_page_config(page_title="AI 취약점 분석 MVP", page_icon="🔎", layout="wide")
    init_db()

    st.title("웹 기반 취약점 분석 프로그램")
    st.caption("MVP: SQL Injection, Command Injection, Path Traversal 규칙 기반 분석")

    tab_scan, tab_stats = st.tabs(["코드 분석", "통계"])

    with tab_scan:
        source_code = st.text_area(
            "분석할 Python 코드",
            value=DEFAULT_CODE,
            height=360,
            help="Python 코드를 붙여넣고 분석 버튼을 누르세요.",
        )

        if st.button("분석하기", type="primary"):
            findings = analyze_code(source_code)
            save_scan(source_code, findings)

            if not findings:
                st.success("탐지된 취약점 후보가 없습니다.")
            else:
                st.warning(f"{len(findings)}개의 취약점 후보를 찾았습니다.")
                for finding in findings:
                    with st.container(border=True):
                        st.subheader(f"{finding.vulnerability} · {finding.severity.upper()}")
                        st.write(f"라인: {finding.line}")
                        st.code(finding.code or "(코드 위치를 추출하지 못했습니다.)", language="python")
                        st.write(f"이유: {finding.reason}")
                        st.write(f"개선 방법: {finding.recommendation}")

    with tab_stats:
        stats = load_stats()
        recent = load_recent_scans()

        if stats:
            stats_df = pd.DataFrame(stats)
            st.subheader("취약점 유형별 누적 탐지 수")
            st.bar_chart(stats_df, x="vulnerability", y="count")
            st.dataframe(stats_df, use_container_width=True, hide_index=True)
        else:
            st.info("아직 저장된 분석 결과가 없습니다.")

        st.subheader("최근 분석 기록")
        if recent:
            st.dataframe(pd.DataFrame(recent), use_container_width=True, hide_index=True)
        else:
            st.write("최근 기록이 없습니다.")


if __name__ == "__main__":
    main()
