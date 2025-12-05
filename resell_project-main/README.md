# 🎃 중고거래 마켓플레이스

이 프로젝트는 Docker를 사용하여 컨테이너화된 웹 기반 중고거래 마켓플레이스입니다. Python Flask 백엔드, MySQL 데이터베이스, 그리고 Nginx 웹 서버로 구성되어 있습니다.

## ✨ 주요 기능

- **사용자 인증**:
  - 회원가입, 로그인, 로그아웃 기능
  - 로그인 상태 유지 및 접근 제어

- **상품(게시글) 관리**:
  - 상품 목록 조회 및 상세 정보 확인
  - 상품 등록, 수정 및 삭제 (본인만 가능)
  - 상품 검색 기능 (제목 및 내용 기반)

- **채팅 기능**:
  - 상품 판매자와 1:1 채팅방 생성 및 대화
  - 참여하고 있는 모든 채팅방 목록 확인
  - 읽지 않은 메시지 수 표시
  - 실시간에 가까운 메시지 업데이트 (3초 폴링)

- **기타**:
  - 🎃 파비콘 적용
  - 게시글 조회수 기능
  - 한국 시간(KST) 기준 시간 표시

## 🛠️ 기술 스택

- **Frontend**: `HTML`, `CSS`, `JavaScript`
- **Backend**: `Python`, `Flask`
- **Database**: `MySQL 8.0`
- **Infrastructure**: `Docker`, `Docker Compose`, `Nginx`

## 🚀 실행 방법

### 필요 조건

- [Docker](https://www.docker.com/get-started)
- [Docker Compose](https://docs.docker.com/compose/install/)

### 로컬 환경에서 실행하기

1.  **프로젝트 클론 또는 다운로드**

2.  **Docker 컨테이너 빌드 및 실행**:
    프로젝트의 루트 디렉토리에서 다음 명령어를 실행합니다. `-d` 옵션은 컨테이너를 백그라운드에서 실행합니다.

    ```bash
    docker compose up -d --build
    ```

3.  **웹사이트 접속**:
    웹 브라우저를 열고 다음 주소로 접속합니다.
    [http://localhost](http://localhost)

4.  **서비스 중지**:
    컨테이너를 중지하고 관련 네트워크를 제거하려면 다음 명령어를 실행합니다.

    ```bash
    docker compose down
    ```

5.  **(선택) 데이터베이스 초기화**:
    모든 데이터를 완전히 삭제하고 데이터베이스를 초기 상태로 되돌리려면 다음 명령어를 사용합니다. **주의: 데이터베이스 볼륨에 저장된 모든 데이터가 영구적으로 삭제됩니다.**

    ```bash
    docker compose down -v
    ```

## 📁 프로젝트 구조

```
.
├── docker-compose.yml      # Docker 서비스 정의
├── db/
│   └── init.sql            # 데이터베이스 스키마 및 초기 데이터
├── nginx/
│   └── nginx.conf          # Nginx 설정 파일
└── web/
    ├── app.py              # Flask 메인 애플리케이션
    ├── Dockerfile          # Flask 앱을 위한 Dockerfile
    ├── requirements.txt    # Python 의존성 목록
    ├── static/             # CSS, JS, 이미지 등 정적 파일
    └── templates/          # HTML 템플릿 파일
        ├── index.html
        ├── product_list.html
        ├── product_detail.html
        ├── chat_list.html
        ├── chat_room.html
        └── ...
```