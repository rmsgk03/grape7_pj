# AI Vulnerability Scanner MVP

웹 기반 취약점 분석 프로그램의 첫 번째 MVP입니다.

## 현재 분석 대상

- SQL Injection
- Command Injection
- Path Traversal

## 실행 방법

```powershell
cd "C:\Users\BaeGeunha\Desktop\grape 프로젝트\ai-vuln-scanner"
python server.py
```

브라우저에서 `http://127.0.0.1:8501`로 접속하면 됩니다.

## 현재 구조

```text
server.py               의존성 없는 웹 MVP
app.py                  Streamlit 웹 화면 초안
scanner/rules.py        규칙 기반 취약점 분석기
scanner/storage.py      SQLite 저장 및 통계 기능
samples/                테스트용 취약 코드 예시
```

## 다음에 추가할 기능

- 안전 코드 예시와 취약 코드 예시 데이터셋 정리
- 규칙 기반 분석 결과와 AI 모델 분석 결과 비교
- CodeBERT 기반 취약점 분류 모델 연결
- 분석 결과 리포트 다운로드
