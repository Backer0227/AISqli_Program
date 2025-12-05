# 보안 스캐너 (Security Scanner)

웹 애플리케이션의 SQL Injection 및 XSS 취약점을 자동으로 진단하는 도구입니다.

## 기능

- **SQL Injection 탐지**
  - Error-based SQLi
  - Time-based Blind SQLi
  - Boolean-based Blind SQLi
  - Union-based SQLi

- **XSS (Cross-Site Scripting) 탐지**
  - Reflected XSS
  - 다양한 필터 우회 기법

- **인증 지원**
  - 로그인 세션 관리
  - 인증이 필요한 엔드포인트 자동 처리

- **엔드포인트 자동 탐지** ⭐ NEW
  - HTML 크롤링으로 링크 및 폼 자동 발견
  - Flask 소스 코드 분석으로 라우트 자동 추출
  - 수동 설정과 자동 탐지 모두 지원

- **리포트 생성**
  - JSON 형식
  - CSV 형식
  - 상세한 취약점 정보 및 증거 포함

## 설치

1. Python 3.7 이상이 필요합니다.

2. 필요한 패키지 설치:
```bash
pip install -r requirements.txt
```

## 설정

`config/config.yaml` 파일을 수정하여 스캔 대상을 설정합니다.

### 주요 설정 항목

- **target**: 대상 서버 정보
  - `base_url`: 대상 서버의 기본 URL
  - `timeout`: 요청 타임아웃 (초)
  - `verify_ssl`: SSL 인증서 검증 여부

- **auth**: 인증 정보 (로그인이 필요한 경우)
  - `enabled`: 인증 사용 여부
  - `login_url`: 로그인 엔드포인트
  - `login_username`: 로그인 사용자명
  - `login_password`: 로그인 비밀번호

- **endpoints**: 스캔할 엔드포인트 설정
  - `auto_detect`: 자동 탐지 활성화 여부 (true/false)
  - `discovery`: 자동 탐지 설정
    - `enable_crawling`: HTML 크롤링 활성화
    - `enable_source_analysis`: Flask 소스 코드 분석 활성화
    - `source_path`: Flask 앱 파일 경로 (선택사항)
  - `manual`: 수동 설정 엔드포인트 목록 (auto_detect가 false일 때 사용)
    - `path`: 엔드포인트 경로
    - `method`: HTTP 메서드 (GET, POST 등)
    - `params`: 테스트할 파라미터 목록
    - `requires_auth`: 인증 필요 여부

## 사용 방법

### 기본 실행 (SQL Injection + XSS 스캔)

```bash
python main.py
```

### SQL Injection만 스캔

```bash
python main.py --sqli-only
```

### XSS만 스캔

```bash
python main.py --xss-only
```

### 커스텀 설정 파일 사용

```bash
python main.py -c path/to/custom_config.yaml
```

## 결과 확인

스캔 결과는 `results/` 디렉토리에 저장됩니다:

- `scan_report_YYYYMMDD_HHMMSS.json`: JSON 형식 리포트
- `scan_report_YYYYMMDD_HHMMSS.csv`: CSV 형식 리포트

## 주의사항

⚠️ **이 도구는 합법적인 보안 점검 및 연구 목적으로만 사용해야 합니다.**

- 테스트 대상 서버의 소유자 또는 관리자의 명시적인 허가를 받은 후에만 사용하세요.
- 운영 환경에서 무단으로 사용하지 마세요.
- 테스트 결과는 적절히 관리하고 보호하세요.

## 프로젝트 구조

```
security_scanner/
├── config/
│   └── config.yaml          # 설정 파일
├── payloads/
│   ├── sqli_payloads.txt    # SQL Injection 페이로드
│   └── xss_payloads.txt     # XSS 페이로드
├── scanners/
│   ├── base_scanner.py      # 기본 스캐너 클래스
│   ├── sqli_scanner.py      # SQL Injection 스캐너
│   └── xss_scanner.py       # XSS 스캔너
├── utils/
│   ├── config_loader.py     # 설정 로더
│   ├── http_client.py       # HTTP 클라이언트
│   ├── auth_handler.py      # 인증 핸들러
│   ├── payload_loader.py    # 페이로드 로더
│   └── report_generator.py # 리포트 생성기
├── results/                 # 스캔 결과 저장 디렉토리
├── main.py                  # 메인 실행 스크립트
├── requirements.txt         # 필요한 패키지 목록
└── README.md               # 이 파일
```

## 기술 스택

- Python 3.7+
- requests: HTTP 요청 처리
- PyYAML: 설정 파일 파싱
- beautifulsoup4: HTML 크롤링 및 파싱
- lxml: XML/HTML 파서

## 라이선스

이 프로젝트는 교육 및 연구 목적으로 제공됩니다.

"# AISqli_Program" 
