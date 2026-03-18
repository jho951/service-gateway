# Api-gateway-server

내부 서비스를 외부 단일 진입점으로 연결하는 정책형 API Gateway 서버입니다.

## 설치 및 실행

### 요구 사항

- Java 17
- Docker, Docker Compose

### 로컬 실행

필수 환경 변수를 설정합니다.

```bash
export AUTH_SERVICE_URL=http://localhost:8081
export USER_SERVICE_URL=http://localhost:8082
export BLOCK_SERVICE_URL=http://localhost:8083
export GATEWAY_PORT=8080
```

애플리케이션을 실행합니다.

```bash
./gradlew run
```

### Docker 실행

`docker` 디렉토리 기준으로 실행합니다.

```bash
bash docker/run.sh
```

기본 포트는 `http://localhost:8080` 입니다.

## 핵심 기능

- `/auth`, `/users`, `/blocks` 등 경로 기반 업스트림 라우팅
- Auth Service 기반 세션 인증 위임
- 외부 신뢰 헤더 제거 후 내부 trusted header 재주입
- CORS, 보안 헤더, 요청 ID, rate limit 같은 공통 정책 처리
- Block Service를 포함한 downstream 서비스 프록시 처리

## 상세 문서

- [API 문서](/Users/jhons/Downloads/BE/Api-gateway-server/docs/API.md)
- [설계 문서](/Users/jhons/Downloads/BE/Api-gateway-server/docs/Design.md)
- [인증/권한 전략](/Users/jhons/Downloads/BE/Api-gateway-server/docs/Authz-Strategy.md)
- [오류 코드](/Users/jhons/Downloads/BE/Api-gateway-server/docs/Error-Codes.md)
- [확장 가이드](/Users/jhons/Downloads/BE/Api-gateway-server/docs/Expansion.md)
