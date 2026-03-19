# Api-gateway-server

내부 서비스를 외부 단일 진입점으로 연결하는 API Gateway 서버입니다.


## 세부 문서

1. [빠른 시작](https://github.com/jho951/Api-gateway-server/wiki/)

7. [API 요약](https://github.com/jho951/Api-gateway-server/wiki/API)
8. [프록시 규칙](/Users/jhons/Downloads/BE/Api-gateway-server/docs/Proxy-Rules.md)

## 빠른 시작

### 요구 사항

- Java 17
- Docker, Docker Compose

### 로컬 실행

```bash
bash scripts/run.local.sh dev
```

### Docker 실행

```bash
bash scripts/run.docker.sh dev
```

기본 포트는 `http://localhost:8080` 입니다.

## 현재 구조

- Gateway는 외부 요청의 단일 진입점입니다.
- 외부 사용자가 보는 흐름은 `public`, `protected`, `admin` 세 가지입니다.
- `/auth`, `/users`, `/blocks` 같은 경로를 각 내부 서비스로 전달합니다.
- 보호 경로에서는 Auth Service로 세션을 검증합니다.
- 관리 경로에서는 필요하면 Redis 캐시와 Permission Service를 통해 권한을 추가 확인합니다.
- `internal` 경로는 사용자 기능 API가 아니라 Gateway와 내부 서비스 사이의 계약입니다.
- `dev`와 `prod` 설정은 `env/dev.env`, `env/prod.env`로 분리되어 있습니다.
