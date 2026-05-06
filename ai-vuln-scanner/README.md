# AI Vulnerability Scanner MVP

규칙 기반으로 Python 코드의 취약점 패턴을 탐지하는 MVP 프로젝트입니다.

## 지원하는 취약점

- SQL Injection
- Command Injection
- Path Traversal

## 다른 컴퓨터에서 실행하기

```powershell
git clone https://github.com/rmsgk03/grape7_pj.git
cd grape7_pj/ai-vuln-scanner

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

python server.py
```

브라우저에서 `http://127.0.0.1:8501`로 접속하면 됩니다.

## macOS 또는 Linux에서 실행하기

```bash
git clone https://github.com/rmsgk03/grape7_pj.git
cd grape7_pj/ai-vuln-scanner

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python server.py
```

## 프로젝트 구조

```text
server.py                    서버 실행 파일
app.py                       Streamlit UI 초안
scanner/rules.py             규칙 기반 취약점 분석기
scanner/storage.py           SQLite 저장 및 통계 기능
samples/vulnerable_examples.py 테스트용 취약 코드 예시
```

## 참고

- `.log` 파일은 실행 중 생성되는 로그 파일이라 Git에 포함하지 않습니다.
- `scan_results.sqlite3`는 로컬 분석 결과 DB라 Git에 포함하지 않습니다.
