# Api Gateway Server

API Gateway는 외부 요청의 단일 진입점입니다.

## 기준 용어

- `Gateway`
  - 외부 요청을 받고 인증, 라우팅, 프록시, 응답 정책을 적용하는 서버입니다.
- `upstream`
  - Gateway가 프록시로 전달하는 대상 서비스입니다.
- `downstream`
  - Gateway 뒤에서 실제 비즈니스 처리를 수행하는 내부 서비스입니다.
- `RouteType`
  - `PUBLIC`, `PROTECTED`, `ADMIN`, `INTERNAL` 라우트 구분입니다.
- `X-User-Id`
  - Gateway가 인증 성공 후 내부 서비스에 주입하는 사용자 식별 헤더입니다.
- `X-Request-Id`
  - 단일 요청 추적용 헤더입니다.
- `X-Correlation-Id`
  - 여러 서비스에 걸친 추적용 상관관계 헤더입니다.
- `GatewayErrorCode`
  - Gateway가 실패 응답에 사용하는 표준 에러 코드 집합입니다.
- `passthrough`
  - 업스트림 성공 응답의 `status`, `headers`, `body`를 Gateway가 그대로 전달하는 방식입니다.

## 계약 동기화

- 이 레포의 계약 동기화 기준 파일은 루트 [contract.lock.yml](contract.lock.yml) 입니다.
- 계약 변경 절차: [contract-change-workflow.md](docs/contract-change-workflow.md)
- 계약 영향 변경이 있으면 contract 레포를 먼저 갱신하고, 그 다음 `contract.lock.yml`의 ref/commit을 맞춥니다.
- PR에서는 `.github/workflows/contract-check.yml`이 lock 파일과 계약 영향 변경 여부를 검사합니다.
- 위키 문서와 README는 같은 용어를 사용합니다.

## 실행 요구 사항

- Java 17
- Docker
- Docker Compose

## 기본 포트

- `http://localhost:8080`

## 사전 준비

- `auth-service` 기동
- `permission-service` 기동
- `user-service` 기동
- `block-service` 기동
- `redis` 기동
- Gateway 전용 환경변수 설정
- 운영 환경에서는 `AUTH_JWT_VERIFY_ENABLED=true`
- 운영 환경에서는 `PERMISSION_SERVICE_URL=http://permission-service:8084`
- 운영 환경에서는 `PERMISSION_ADMIN_VERIFY_URL=http://permission-service:8084/permissions/internal/admin/verify`

## 실행

### docker dev

```bash
bash scripts/run.docker.sh dev
```

### docker prod

```bash
bash scripts/run.docker.sh prod
```

### local

```bash
bash scripts/run.local.sh
```

## 기동 확인

- `GET /health`
- `GET /ready`

예시:

```bash
curl -i http://localhost:8080/health
curl -i http://localhost:8080/ready
```

## 응답 정책

### 성공

- 성공 응답은 upstream 응답을 그대로 전달합니다. (`passthrough`)
- Gateway가 성공 JSON envelope를 다시 만들지 않습니다.
- 업스트림의 `status`, `headers`, `body`를 그대로 반환합니다.

### 실패

- 실패 응답은 `GatewayErrorCode`와 `GatewayErrorResponse`로 생성합니다.
- 실패 JSON에는 `code`, `message`, `path`, `requestId`가 포함됩니다.

## 인증 정책

### 브라우저

- 브라우저는 쿠키 기반을 우선합니다.
- `ACCESS_TOKEN` 또는 `sso_session` 쿠키를 Gateway로 보냅니다.
- 브라우저 요청은 `credentials: 'include'`가 필요합니다.

### 비브라우저

- 모바일, CLI, 서버 간 호출은 `Authorization: Bearer <token>`을 우선합니다.

### 내부 정규화

- Gateway는 인증 성공 후 내부 서비스에 검증된 `X-User-Id`를 주입합니다.
- 외부에서 들어온 `X-User-*` 계열 trusted header는 신뢰하지 않습니다.
- 내부 서비스는 Gateway가 주입한 컨텍스트만 신뢰합니다.
- `/v1/users/me`에서 비활성 사용자 여부는 user-service가 DB 상태로 판단합니다.
- user-service가 비활성 사용자를 `403`으로 거부하면 Gateway는 해당 응답을 그대로 전달합니다.

## 라우팅 정책

- `PUBLIC`
  - 인증 검증이 없습니다.
- `PROTECTED`
  - 사용자 인증이 필요합니다.
  - Gateway가 `AuthSessionValidator`로 Bearer 또는 쿠키를 검증합니다.
- `ADMIN`
  - 관리자용 정책 경로입니다.
  - 인증 성공 후 permission-service로 최종 인가를 위임합니다.
- `INTERNAL`
  - 내부 서비스 전용 경로입니다.

## 내부 호출 경로

- auth-service 내부 검증:
  - `/auth/internal/session/validate`
- permission-service 관리자 검증:
  - `/permissions/internal/admin/verify`
  - 전달 헤더: `X-User-Id`, `X-Session-Id`, `X-Original-Method`, `X-Original-Path`, `X-Request-Id`, `X-Correlation-Id`, `X-Internal-Request-Secret`
  - `GATEWAY_INTERNAL_REQUEST_SECRET`는 permission-service의 `PERMISSION_INTERNAL_REQUEST_SECRET`와 같은 값을 사용합니다.

## 권한 정책

- `GATEWAY_PERMISSION_CACHE_ENABLED`가 켜져 있으면 관리자 경로 판정 결과를 짧게 캐시할 수 있습니다.
- 캐시의 기본 프리픽스는 `gateway:admin-permission:` 입니다.
- permission-service가 응답하지 않으면 `ADMIN` 경로는 fail-closed로 거부됩니다.

## 추적 헤더

- 모든 응답에는 추적 헤더가 포함됩니다.
  - `X-Request-Id`
  - `X-Correlation-Id`

## 주의사항

- 외부 `X-User-Id`는 신뢰하지 않습니다.
- 내부 서비스는 Gateway가 주입한 `X-User-Id`만 사용합니다.
- Gateway는 쿠키나 외부 Bearer 토큰을 downstream에 그대로 신뢰시키지 않습니다.
- `GatewayErrorCode`는 `GatewayExceptionHandler`를 통해 JSON 에러 응답으로 변환됩니다.
