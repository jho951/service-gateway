# Api-gateway-server

내부 서비스를 외부 단일 진입점으로 연결하는 API Gateway 서버입니다.

## Contract Source

- 공통 계약 레포: `https://github.com/jho951/contract`
- 이 서비스의 코드 SoT: `Api-gateway-server` `main`
- 인터페이스 변경 시 본 저장소 구현보다 계약 레포 변경을 먼저 반영합니다.

### 현재 구조

- Gateway는 외부 요청의 단일 진입점입니다.
- 외부 사용자가 보는 흐름은 `public`, `protected` 두 가지가 중심입니다.
- `/v1/auth`, `/v1/users`, `/v1/internal/users`, `/v1/documents`, `/v1/admin` 같은 경로를 각 내부 서비스로 전달합니다.
- 브라우저 기반 클라이언트는 `credentials: 'include'` 와 쿠키만으로 동작하는 흐름을 우선합니다. `auth-service`가 내려주는 `sso_session`, `ACCESS_TOKEN`, `refresh_token` 쿠키를 브라우저가 보관하고, 이후 `/v1/auth/me`, 로그아웃, 보호 API는 이 쿠키를 기준으로 동작합니다.
- 비브라우저 클라이언트나 운영 편의용 fallback으로는 `Authorization` 헤더도 허용합니다. gateway는 들어온 `Authorization` 이 있으면 우선 사용하고, 없으면 쿠키를 검사합니다.
- 실제 로그인/권한/세션 상태와 리프레시 토큰 관리는 auth-service가 Redis 기반으로 단독 관리합니다.
- 권한 검증은 아직 게이트웨이에서 강제되지 않습니다.
- auth-service 관련 `/v1/auth/**`, `/v1/oauth2/**`, `/v1/login/oauth2/**` 경로는 내부 전달 전에 `/v1` prefix를 제거해서 프록시합니다.
- auth-service 관련 `Set-Cookie`, `Cookie`, `Location`, `302`, `204` 응답은 그대로 통과시킵니다.
- 리프레시 토큰은 gateway가 저장하거나 Redis에 접근하지 않고, `/v1/auth/refresh` 요청은 그대로 auth-service로 프록시되어 갱신/저장을 auth-service만 수행합니다.
- credentials 기반 브라우저 호출을 위해 CORS는 명시 origin + `Access-Control-Allow-Credentials: true` 기준으로 동작합니다.
- `user-service` 공개 API는 `/v1/users/**`로, 내부 API는 `/v1/internal/users/**`로 유지합니다.
- OAuth2 사용자 프로비저닝 단일 호출 경로 `/v1/internal/users/find-or-create-and-link-social` 도 내부 사용자 API로 동일 정책을 적용합니다.
- `user-service` 라우트에는 `Authorization` 헤더를 그대로 전달하고, 내부 사용자 API는 허용된 내부 IP 대역에서만 통과시킵니다.
- `internal` 경로는 사용자 기능 API가 아니라 Gateway와 내부 서비스 사이의 계약입니다.
- `local`과 `prod` 설정은 루트의 `.env.local`, `.env.prod`로 분리되어 있습니다.

## 세부 문서
[WIKI](https://github.com/jho951/Api-gateway-server/wiki/)

## JWT 검증

- 보호 경로에서 들어오는 `Authorization: Bearer` JWT는 gateway가 공유 비밀 키(HS256/HS384/HS512) 또는 auth-service의 공개키(RS256/RS384/RS512)로 서명과 `iss`/`aud`/`exp` 클레임을 검증한 뒤에 `sub`/`userId` 같은 사용자 claim을 `X-User-Id`로 재구성하여 하위 서비스로 전달합니다. 브라우저 흐름에서는 쿠키 기반이 우선이고, JWT 헤더는 비브라우저 fallback 입니다. 로그인 · 권한 · 리프레시 상태는 Redis 기반의 auth-service가 단독으로 관리하며, gateway는 세션 상태를 직접 조회하지 않습니다.

### 환경 변수

- `AUTH_JWT_VERIFY_ENABLED`: `true`로 설정하면 서명 검증을 시도합니다. 기본값은 `false`이며, 키를 제공하지 않으면 인증 전 검증을 건너뜁니다.
- `AUTH_JWT_PUBLIC_KEY_PEM`: auth-service의 공개키 PEM 텍스트입니다. 여러 줄이라면 `\n`과 함께 큰따옴표로 감싸서 넣어주세요. RS 계열 알고리즘을 사용할 때 제공해야 합니다.
- `AUTH_JWT_SHARED_SECRET`: HS256/HS384/HS512 같은 HS 계열 알고리즘을 검증할 때 사용하는 대칭 키입니다. `AUTH_JWT_ALGORITHM`이 HS 계열일 경우 필수입니다.
- `AUTH_JWT_KEY_ID`: JWT 헤더의 `kid`와 비교해 특정 키만 허용하도록 합니다([선택 사항](https://www.rfc-editor.org/rfc/rfc7515)).
- `AUTH_JWT_ALGORITHM`: 기대하는 JWT `alg` 값(RS256, RS384, RS512, HS256, HS384, HS512 중 하나). 기본값은 `RS256`입니다.
- `AUTH_JWT_ISSUER`: `iss` 클레임이 반드시 이 값과 일치해야 인증을 성공으로 판단합니다([선택 사항]).
- `AUTH_JWT_AUDIENCE`: `aud` 클레임에 이 값을 반드시 포함시켜야 합니다([선택 사항], 문자열 또는 배열 모두 지원).
- `AUTH_JWT_CLOCK_SKEW_SECONDS`: `exp` 비교 시 허용할 최대 시계 차 입니다. 기본값은 `30`.
- `GATEWAY_OAUTH_DEBUG_LOG_ENABLED`: `true`로 설정하면 `/v1/auth/sso/start`, `/v1/oauth2/**`, `/v1/login/oauth2/**`, `/v1/auth/exchange` 요청/응답에 대해 `oauth_trace` 로그를 INFO 레벨로 출력합니다(쿠키/코드 값은 출력하지 않고 존재 여부만 출력).

## Response Codes

### 구조
응답 형식을 통일하기 위해 코드([SuccessCode.java](https://github.com/jho951/Api-gateway-server/blob/main/src/main/java/com/gateway/code/SuccessCode.java), [ErrorCode.java](https://github.com/jho951/Api-gateway-server/blob/main/src/main/java/com/gateway/code/ErrorCode.java))와 응답 바디 객체([GlobalResponse.java](https://github.com/jho951/Api-gateway-server/blob/main/src/main/java/com/gateway/dto/GlobalResponse.java))를 분리한 구조입니다.

- 실제 응답 JSON은 `GlobalResponse`가 한 번 감싸서 같은 모양으로 내려줍니다.
- `SuccessCode`는 성공 응답의 표준 메타정보로 `httpStatus`, `code`, `message`를 관리합니다.
- `ErrorCode`는 실패 응답의 표준 메타정보로 `httpStatus`, `code`, `message`를 관리합니다.
- `GlobalResponse`는 실제 API 응답 바디로 `success`, `httpStatus`, `message`, `code`, `data`를 관리합니다.
- `success` 필드는 `GlobalResponse`에서만 관리합니다.
- 성공 코드는 `1000`번대, 실패 코드는 `6000`번대를 사용합니다.

### SuccessCode

#### Source Of Truth

최종 기준은 [SuccessCode.java](https://github.com/jho951/Api-gateway-server/blob/main/src/main/java/com/gateway/code/SuccessCode.java) 입니다.

문서와 코드가 다르면 코드를 수정하기 전에 이 문서를 먼저 갱신합니다.

#### 필드

- `httpStatus`: HTTP 상태 코드
- `message`: 사용자/클라이언트가 해석할 수 있는 메시지
- `code`: 게이트웨이 성공 코드

#### 응답 구조

```json
{
  "httpStatus": 200,
  "success": true,
  "message": "조회 요청 성공",
  "code": 1000,
  "data": {
    "status": "UP"
  }
}
```

#### Fixed Success Codes

| Enum | HTTP | Code | Message | Meaning |
|---|---:|---:|---|---|
| `GET_SUCCESS` | 200 | 1000 | 조회 요청 성공 | 일반 조회 성공 |
| `CREATE_SUCCESS` | 201 | 1001 | 리소스 생성 성공 | 생성 요청 성공 |
| `UPDATE_SUCCESS` | 200 | 1002 | 리소스 수정 성공 | 수정 요청 성공 |
| `DELETE_SUCCESS` | 200 | 1003 | 리소스 삭제 성공 | 삭제 요청 성공 |
| `PROCESS_ACCEPTED` | 202 | 1004 | 요청 접수 성공 | 비동기 또는 후속 처리용 요청 접수 |

### ErrorCode

#### Source Of Truth

최종 기준은 [ErrorCode.java](https://github.com/jho951/Api-gateway-server/blob/main/src/main/java/com/gateway/code/ErrorCode.java) 입니다.

문서와 코드가 다르면 코드를 수정하기 전에 이 문서를 먼저 갱신합니다.

#### 필드

- `httpStatus`: HTTP 상태 코드
- `message`: 사용자/클라이언트가 해석할 수 있는 메시지
- `code`: 게이트웨이 비즈니스 오류 코드

`success`와 `data`는 `GlobalResponse`에서 관리합니다. 오류 응답에서는 `success`는 항상 `false`, `data`는 항상 `null`입니다.

#### 응답구조

```json
{
  "httpStatus": 401,
  "success": false,
  "message": "인증이 필요합니다.",
  "code": 6004,
  "data": null
}
```

#### Fixed Error Codes

| Enum | HTTP | Code | Message | Meaning |
|---|---:|---:|---|---|
| `INVALID_REQUEST` | 400 | 6000 | 잘못된 요청입니다. | 게이트웨이 입력 형식이 잘못된 경우 |
| `VALIDATION_ERROR` | 400 | 6001 | 요청 필드 유효성 검사에 실패했습니다. | 요청 검증 실패 |
| `METHOD_NOT_ALLOWED` | 405 | 6002 | 허용되지 않은 HTTP 메서드입니다. | 지원하지 않는 HTTP 메서드 |
| `NOT_FOUND_URL` | 404 | 6003 | 요청하신 URL을 찾을 수 없습니다. | 매핑된 gateway route가 없음 |
| `UNAUTHORIZED` | 401 | 6004 | 인증이 필요합니다. | protected/admin 경로에서 인증 실패 |
| `FORBIDDEN` | 403 | 6005 | 접근이 허용되지 않습니다. | internal 경로 접근, IP 차단, admin 권한 부족 |
| `TOO_MANY_REQUESTS` | 429 | 6006 | 요청이 너무 많습니다. | 로그인 시도 rate limit 초과 |
| `PAYLOAD_TOO_LARGE` | 413 | 6007 | 요청 본문이 허용 크기를 초과했습니다. | body size 제한 초과 |
| `UPSTREAM_TIMEOUT` | 504 | 6008 | 업스트림 응답 시간이 초과되었습니다. | Auth/Permission/Upstream timeout |
| `UPSTREAM_FAILURE` | 502 | 6009 | 업스트림 호출에 실패했습니다. | 업스트림 I/O 실패 또는 비정상 호출 실패 |
| `FAIL` | 500 | 6999 | 요청 처리 중 오류가 발생했습니다. | 분류되지 않은 gateway 내부 예외 |

#### Mapping Rules

- `UNAUTHORIZED`: Auth Service 검증 결과가 인증 실패일 때 사용합니다.
- `FORBIDDEN`: 인증은 되었지만 접근 권한이 없거나, internal/admin/IP 정책에 의해 차단될 때 사용합니다.
- `UPSTREAM_TIMEOUT`: `InterruptedException` 또는 타임아웃 성격의 업스트림 실패에 사용합니다.
- `UPSTREAM_FAILURE`: 일반적인 업스트림 I/O 실패에 사용합니다.
- `FAIL`: 위 규칙으로 분류되지 않은 예외에 사용합니다.

## 빠른 시작

### 요구 사항

- Java 17
- Docker, Docker Compose

### 로컬 실행

```bash
bash scripts/run.local.sh local
```

### Docker 실행

```bash
bash scripts/run.docker.sh local
```

기본 포트는 `http://localhost:8080` 입니다.

`scripts/run.docker.sh` 는 공유 external 네트워크(`SHARED_SERVICE_NETWORK`, 기본값 `service-backbone-shared`)가 없으면 자동 생성합니다.

## Secure Deployment Baseline

documents-service와 auth-service의 direct access를 막으려면 gateway만 외부 포트를 열고, upstream 서비스는 내부 네트워크에만 두는 구성이 필요합니다.

이 저장소의 단일 compose 파일([docker-compose.yml](/Users/jhons/Downloads/BE/Api-gateway-server/docker/docker-compose.yml))은 기본 gateway 실행과 `local-stack` profile 실행을 함께 지원합니다.

구성 원칙:

- `gateway`만 `8080:8080`으로 외부 공개
- `gateway`, `auth-service`, `user-service`, `documents-service`, `permission-service`는 공유 external 네트워크(`service-backbone-shared`)로만 서비스 간 통신
- 각 서비스 DB는 서비스별 private internal 네트워크(`auth-private`, `user-private`, `documents-private`, `permission-private`)에만 연결
- 서비스 컨테이너는 `service-backbone-shared` + 자기 private 네트워크에만 연결되고, DB는 private 네트워크만 연결

예시 실행:

```bash
docker network create service-backbone-shared || true
docker compose -f docker/docker-compose.yml --profile local-stack up --build
```

이 예시를 운영 배포 기준으로 사용할 때는 이미지 이름, 내부 포트, ingress/security group, allowlist, mTLS 같은 환경별 정책을 함께 맞춰야 합니다.

## Docker 점검 순서

Docker에서 Gateway를 올린 뒤에는 아래 순서로 확인합니다.

1. Gateway 재빌드 후 실행

```bash
bash scripts/run.docker.sh local
```

2. 헬스 체크 확인

```bash
curl -i http://localhost:8080/health
curl -i http://localhost:8080/ready
```

3. 업스트림 서비스 포트 확인

- `auth-service`: `8081`
- `user-service`: `8082`
- `block-service`: `8083`
- `permission-service`: `8084`

예:

```bash
curl -i http://localhost:8081
curl -i http://localhost:8082
```

4. 로그인 시작 경로 확인

```bash
curl -i "http://localhost:8080/v1/auth/sso/start?page=editor&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fauth%2Fcallback"
```

여기서 `502`가 나오면 Gateway에서 업스트림 연결이 실패한 것입니다.
여기서 `403 IP_BLOCKED`가 나오면 보통 `auth-service`의 IP guard 정책 문제입니다.

5. 보호 API 호출 확인

```bash
curl -i http://localhost:8080/v1/documents \
  -H "Authorization: Bearer <access-token>"
```

문서 API는 외부에서 `/v1/documents/**`, `/v1/admin/**`로 받고 block service에는 `/v1`을 제거한 내부 경로(`/documents/**`, `/admin/**`)로 전달합니다.
예를 들어 `GET /v1/documents/123` 요청은 block service의 `GET /documents/123`로 전달됩니다.
외부에서 들어온 `X-User-Id`는 신뢰하지 않고 제거하며, 게이트웨이가 auth-service 검증 결과로 내부 `X-User-Id`를 다시 주입합니다.
기본 설정에서는 downstream 서비스로 `Authorization` 헤더를 전달하지 않습니다.
보호 경로에서는 아래 순서로 인증을 처리합니다.

- `Authorization: Bearer <token>` 형식 확인
- 세그먼트 개수, base64url 문자셋, 비어 있는 payload 같은 명백한 비정상 JWT 차단
- 선택적 payload `exp` 만료 체크
- 설정값이 활성화된 경우 JWT 서명/클레임(`iss`, `aud`, `exp`) 검증
- 검증된 토큰 claim으로 `X-User-Id` 내부 헤더 재주입

토큰 신뢰 판단은 gateway의 JWT 검증 설정에 의존합니다.

## Documents Gateway Contract

이 섹션은 현재 block server 연동 기준의 고정 계약을 정리합니다.
block server는 게이트웨이가 맞춰야 하는 대상이며, 이 계약은 gateway 기준에서 협의 대상이 아니라 구현 기준입니다.

### 외부 계약

- 브라우저 클라이언트는 Gateway만 호출하고, 인증은 `credentials: 'include'` 로 전달되는 쿠키를 우선 사용합니다.
- 비브라우저 클라이언트는 필요 시 `Authorization: Bearer <access-token>` 을 사용할 수 있습니다.
- 클라이언트가 보낸 `X-User-Id`는 무시되고 upstream 전달 전에 제거됩니다.
- 문서 API 외부 prefix는 `/v1/documents/**`, `/v1/admin/**` 입니다.

예:

```http
POST /v1/documents
Authorization: Bearer <token>
Content-Type: application/json
```

### 내부 전달 계약

- Gateway는 문서 요청 전달 시 외부 `/v1` prefix를 제거해 block server 내부 경로(`/documents/**`, `/admin/**`)로 전달합니다.
- Gateway는 내부 `X-User-Id`를 재주입합니다.
- 브라우저 기반 쿠키 흐름에서는 `Authorization` 이 없어도 되고, `auth-service`가 발급한 쿠키만으로 인증이 진행됩니다.

예:

```http
POST /documents
X-User-Id: 12345
X-Request-Id: <trace-id>
Content-Type: application/json
```

### 라우팅 범위

현재 documents/block server로 전달하는 외부 경로는 아래와 같습니다.

- `GET /v1/documents`
- `GET /v1/documents/trash`
- `POST /v1/documents`
- `GET /v1/documents/{documentId}`
- `GET /v1/documents/{documentId}/blocks`
- `PATCH /v1/documents/{documentId}`
- `PATCH /v1/documents/{documentId}/visibility`
- `POST /v1/documents/{documentId}/transactions`
- `DELETE /v1/documents/{documentId}`
- `PATCH /v1/documents/{documentId}/trash`
- `POST /v1/documents/{documentId}/restore`
- `POST /v1/documents/{documentId}/move`
- `POST /v1/admin/documents/{documentId}/blocks`
- `PATCH /v1/admin/blocks/{blockId}`
- `DELETE /v1/admin/blocks/{blockId}`
- `POST /v1/admin/blocks/{blockId}/move`

Gateway가 실제로 downstream 에 전달할 때는 외부 `/v1` prefix를 제거해 전달합니다.

예:

- `GET /v1/documents` -> `GET /documents`
- `GET /v1/documents/{documentId}` -> `GET /documents/{documentId}`
- `PATCH /v1/documents/{documentId}` -> `PATCH /documents/{documentId}`
- `DELETE /v1/documents/{documentId}` -> `DELETE /documents/{documentId}`
- `POST /v1/documents/{documentId}/restore` -> `POST /documents/{documentId}/restore`
- `GET /v1/documents/{documentId}/blocks` -> `GET /documents/{documentId}/blocks`
- `PATCH /v1/admin/blocks/{blockId}` -> `PATCH /admin/blocks/{blockId}`
- `DELETE /v1/admin/blocks/{blockId}` -> `DELETE /admin/blocks/{blockId}`

### 응답 계약

- 목표 계약은 `GlobalResponse<T>` envelope 입니다.
- 게이트웨이는 downstream 응답을 가능한 그대로 전달합니다.
- 인증 실패, 경로 미매칭, upstream timeout 같은 gateway 오류만 gateway 응답 코드로 반환합니다.
- plain array 같은 비-envelope 응답은 장기 계약이 아니라 임시 호환으로만 취급해야 합니다.

### 현재 구현 기준

현재 gateway 구현:

- Gateway는 `Authorization` 형식과 payload 를 먼저 선검사합니다.
- Gateway는 설정값이 활성화된 경우 JWT 서명/클레임(`iss`, `aud`, `exp`) 검증이 성공한 요청만 downstream 으로 전달합니다.
- Gateway는 검증된 토큰 claim 기반으로 내부 `X-User-Id`를 주입합니다.
- Gateway는 기본값으로 downstream `Authorization` 헤더를 제거합니다.
- Gateway는 documents service 권한 검증을 대신하지 않습니다.
- documents/block server는 workspace/document/block 단위 권한을 자체 판단해야 합니다.
- 프론트는 `GlobalResponse<T>` envelope 기준으로 처리합니다.

### 서비스 보호 전제

문서 서비스가 `X-User-Id`만 보고 처리하는 구조라면, 배포 경계에서 직접 접근 차단이 반드시 필요합니다.

권장 보호 방식:

- internal network only
- ingress / security group 제한
- gateway only allowlist
- 내부 서명 헤더 검증
- mTLS

현재 이 저장소 안의 코드만으로는 위 전제가 강제되지 않습니다. 운영 환경에서 별도로 막아야 합니다.

### 프론트 연동 주의

- 현재 프론트의 plain array fallback 허용은 임시 호환 로직으로만 유지하는 편이 맞습니다.
- 최종 계약은 `GlobalResponse<T>` only 로 고정하는 것이 좋습니다.
- 문서 수정 API가 partial patch 처럼 보이더라도, 실제 DTO 계약에서는 `title` 필수 여부를 문서 서비스 쪽과 맞춰서 확인해야 합니다.
- block 타입이 늘어날 예정이라면 프론트 serializer/state 에 `block.type`을 명시적으로 보존하는 편이 안전합니다.
