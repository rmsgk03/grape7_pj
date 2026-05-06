# AI Vulnerability Scanner MVP

규칙 기반으로 Python 코드의 취약점 패턴을 탐지하는 MVP 프로젝트입니다.

## 지원하는 취약점

- SQL Injection
- Command Injection
- Path Traversal

## 빠른 시작

```powershell
git clone https://github.com/rmsgk03/grape7_pj.git
cd grape7_pj\ai-vuln-scanner
.\setup.ps1
.\run.ps1
```

실행한 컴퓨터에서는 브라우저에서 `http://127.0.0.1:8501`로 접속하면 됩니다.

CMD를 쓰는 경우:

```cmd
git clone https://github.com/rmsgk03/grape7_pj.git
cd grape7_pj\ai-vuln-scanner
setup.bat
run.bat
```

## 이미 clone 받은 뒤 실행하기

```powershell
cd grape7_pj\ai-vuln-scanner
git pull
.\run.ps1
```

같은 와이파이에 연결된 다른 기기에서 접속하려면 서버를 실행한 컴퓨터의 IP 주소를 확인한 뒤 접속합니다.

```powershell
ipconfig
```

예를 들어 IPv4 주소가 `192.168.0.10`이면 다른 기기 브라우저에서 아래 주소로 접속합니다.

```text
http://192.168.0.10:8501
```

## 수동 실행

스크립트가 안 될 때는 아래처럼 직접 실행할 수 있습니다.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python server.py
```

## 접속이 안 될 때 확인할 것

1. 서버 실행 창에 `Open on this computer: http://127.0.0.1:8501`가 출력되는지 확인합니다.
2. 서버를 실행한 컴퓨터에서 `http://127.0.0.1:8501` 접속이 되는지 먼저 확인합니다.
3. 다른 기기에서 접속할 때는 `127.0.0.1`이 아니라 서버 컴퓨터의 IPv4 주소를 사용합니다.
4. Windows 보안 경고가 뜨면 Python의 개인 네트워크 접근을 허용합니다.
5. 그래도 안 되면 Windows 방화벽에서 TCP 포트 `8501` 인바운드 허용 규칙을 추가합니다.

## 프로젝트 구조

```text
server.py                    서버 실행 파일
app.py                       Streamlit UI 초안
scanner/rules.py             규칙 기반 취약점 분석기
scanner/storage.py           SQLite 저장 및 통계 기능
samples/vulnerable_examples.py 테스트용 취약 코드 예시
ai_training/                 AI 학습 기능 추가 작업 공간
setup.ps1, setup.bat         첫 실행 환경 설정 스크립트
run.ps1, run.bat             서버 실행 스크립트
```

## AI 학습 기능 추가

AI 학습 담당자는 `ai_training/` 폴더에서 데이터 전처리, 학습 실험, 모델 저장 구조를 잡으면 됩니다.
앱에 연결할 최종 추론 코드는 `scanner/` 패키지 안에 추가하는 것을 권장합니다.

자세한 협업 방식은 `CONTRIBUTING.md`와 `ai_training/README.md`를 참고하세요.

## 참고

- `.log` 파일은 실행 중 생성되는 로그 파일이라 Git에 포함하지 않습니다.
- `scan_results.sqlite3`는 로컬 분석 결과 DB라 Git에 포함하지 않습니다.
- 대용량 데이터셋, 학습 모델, 실험 결과는 Git에 포함하지 않습니다.
