# Contributing

## 새 컴퓨터에서 시작하기

```powershell
git clone https://github.com/rmsgk03/grape7_pj.git
cd grape7_pj\ai-vuln-scanner
.\setup.ps1
.\run.ps1
```

CMD를 쓰는 경우:

```cmd
git clone https://github.com/rmsgk03/grape7_pj.git
cd grape7_pj\ai-vuln-scanner
setup.bat
run.bat
```

## 작업 규칙

1. 작업 전 최신 코드를 받습니다.

```powershell
git pull
```

2. 기능 단위로 브랜치를 만듭니다.

```powershell
git checkout -b feature/ai-training
```

3. 변경 후 실행 확인을 합니다.

```powershell
.\run.ps1
```

4. 커밋합니다.

```powershell
git add .
git commit -m "Add AI training scaffold"
git push -u origin feature/ai-training
```

## AI 학습 담당자 참고

- 대용량 데이터셋과 모델 파일은 Git에 올리지 않습니다.
- 작은 예시 데이터만 `samples/`에 추가합니다.
- 학습 실험은 `ai_training/`에서 진행하고, 앱에서 쓰는 최종 추론 코드는 `scanner/`에 연결합니다.
