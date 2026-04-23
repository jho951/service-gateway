# Troubleshooting

처음 보는 실무자는 먼저 `architecture.md`에서 요청 흐름을 보고, 그 다음 `api.md`의 RouteType과 에러 코드를 같이 보면 원인 파악이 빠릅니다.

## `/v1/users/me`가 401을 반환함

확인할 것:

- 브라우저 요청이면 `ACCESS_TOKEN` 또는 `sso_session` 쿠키가 Gateway로 전달되는지 확인합니다.
- 비브라우저 요청이면 `Authorization: Bearer <token>`이 있는지 확인합니다.
- auth-service의 `/auth/internal/session/validate`가 `authenticated: true`와 `userId`를 반환하는지 확인합니다.

## 보호 서비스가 `401 invalid_token` 또는 `iss claim is not valid`를 반환함

증상:

- `POST /v1/documents`, `GET /v1/users/me` 같은 보호 경로가 downstream에서 `401`을 반환합니다.
- 응답 헤더에 `www-authenticate: Bearer error="invalid_token"`이 보입니다.
- 메시지에 `iss claim is not valid`, `aud claim is not valid`, `signature` 같은 JWT 검증 실패가 보입니다.

원인:

- Gateway는 보호 서비스로 `iss=api-gateway`, `aud=internal-services` 내부 JWT를 전달합니다.
- downstream 서비스가 여전히 `auth-service`, `user-service`, `editor-service` 같은 이전 issuer/audience를 기대하면 즉시 거부합니다.
- shared secret이 다르면 issuer/audience를 맞춰도 같은 증상이 납니다.

확인할 것:

- Gateway의 `GATEWAY_INTERNAL_JWT_SHARED_SECRET`, `GATEWAY_INTERNAL_JWT_ISSUER`, `GATEWAY_INTERNAL_JWT_AUDIENCE`
- downstream의 `PLATFORM_SECURITY_JWT_SECRET`, `PLATFORM_SECURITY_JWT_ISSUER`, `PLATFORM_SECURITY_JWT_AUDIENCE`
- `user-service`면 `USER_SERVICE_INTERNAL_JWT_*`, `editor-service`면 platform security JWT 설정이 같은 계약을 보는지 확인합니다.

해결:

- 보호 서비스는 모두 `issuer=api-gateway`, `audience=internal-services` 기준으로 맞춥니다.
- shared secret은 Gateway와 downstream이 같은 값을 사용합니다.
- browser cookie, auth-service access token, Gateway 내부 JWT를 같은 층의 토큰으로 취급하지 않습니다.

## `/v1/users/me`가 403을 반환함

Gateway 인증은 통과했지만 user-service가 사용자를 거부했을 수 있습니다.

- user-service DB에서 사용자 상태를 확인합니다.
- 비활성 사용자라면 user-service가 `403`을 반환하고 Gateway는 그대로 전달합니다.

## 관리자 경로가 403을 반환함

확인할 것:

- `AUTHZ_ADMIN_VERIFY_URL`이 authz-service의 `/permissions/internal/admin/verify`를 가리키는지 확인합니다.
- `GATEWAY_INTERNAL_REQUEST_SECRET`와 authz-service legacy/hybrid 내부 secret이 같은지 확인합니다.
- `AUTHZ_INTERNAL_JWT_SECRET`, `AUTHZ_INTERNAL_JWT_ISSUER`, `AUTHZ_INTERNAL_JWT_AUDIENCE`가 authz-service 운영 설정과 같은지 확인합니다.
- authz-service가 `X-User-Id`, `X-Session-Id`, `X-Original-Method`, `X-Original-Path`를 받는지 확인합니다.
- authz-service가 `200`이 아닌 응답을 반환하면 Gateway는 fail-closed로 거부합니다.
- `authz-service`는 일반 보호 서비스용 `aud=internal-services` 토큰이 아니라, `aud=authz-service` caller proof 토큰을 검증한다는 점을 확인합니다.

## OAuth redirect가 이상함

확인할 것:

- `/v1/oauth2/**`, `/v1/login/oauth2/**`, `/v1/.well-known/jwks.json` 경로가 Gateway를 거치는지 확인합니다.
- upstream auth-service가 `/oauth2/**`, `/login/oauth2/**`, `/.well-known/**` 경로로 redirect하는지 확인합니다.

## upstream 호출이 502를 반환함

Gateway 기준 `1012 UPSTREAM_FAILURE`입니다.

확인할 것:

- upstream base URL이 맞는지 확인합니다.
- 대상 서비스가 실제로 떠 있는지 확인합니다.
- Docker 환경이면 서비스명과 포트가 compose 기준과 일치하는지 확인합니다.
- DNS 실패, 연결 거부, host 오타가 있으면 Gateway는 `502`로 변환합니다.

대표적으로 `AUTH_SERVICE_URL`, `AUTHZ_ADMIN_VERIFY_URL`, `USER_SERVICE_URL`, `AUTHZ_INTERNAL_JWT_*` 오설정에서 자주 발생합니다.

## upstream 호출이 504를 반환함

Gateway 기준 `1013 UPSTREAM_TIMEOUT`입니다.

확인할 것:

- 대상 서비스가 너무 오래 걸리는지 확인합니다.
- `GATEWAY_REQUEST_TIMEOUT_MS` 값이 현재 서비스 응답 시간과 맞는지 확인합니다.
- auth-service 세션 검증, authz-service 관리자 검증, user-service 조회가 timeout 나는지 각각 분리해서 봅니다.
- 느린 쿼리나 외부 연동 때문에 upstream이 지연되면 Gateway는 `504`로 변환합니다.

## platform-security가 실제로 동작하지 않는 것처럼 보임

현재 gateway-service는 Spring Boot + Spring Cloud Gateway 런타임입니다.

```txt
GatewayApplication
  -> GatewayConfig.fromEnv()
  -> Spring Boot WebFlux
  -> Spring Cloud Gateway route/filter chain
  -> GatewayPlatformSecurityWebFilter
  -> GatewayPolicyFilter
```

사용하는 플랫폼 의존성은 다음과 같습니다.

```gradle
implementation platform("io.github.jho951.platform:platform-runtime-bom:3.0.1")
implementation platform("io.github.jho951.platform:platform-governance-bom:3.0.1")
implementation platform("io.github.jho951.platform:platform-security-bom:3.0.1")
implementation "io.github.jho951.platform:platform-governance-starter"
implementation "io.github.jho951.platform:platform-security-starter"
implementation "io.github.jho951.platform:platform-security-hybrid-web-adapter"
implementation "io.github.jho951.platform:platform-security-governance-bridge:3.0.1"
```

현재 상태는 `Hybrid Embedded Gateway Mode` 입니다.

- `GatewayPlatformSecurityWebFilter`가 auth-service 세션 검증, `HybridSecurityRuntime` 평가, admin authz 위임, deny 응답 생성을 담당합니다.
- `GatewayPolicyFilter`는 trusted header 정리, platform downstream header 주입, 내부 JWT 주입, upstream proxy 실행만 담당합니다.
- `platform-security-governance-bridge`는 `SecurityAuditPublisher`를 통해 security verdict를 governance audit recorder로 발행합니다.
- 실패 응답 계약은 `GatewayFailureResponseFactory`와 `GatewayResponseContractWriter`가 공통으로 렌더링합니다.
- 자동 WebFlux starter filter를 주 런타임으로 쓰지 않고, `GatewayApplication`에서 `PlatformSecurityHybridWebAdapterAutoConfiguration`만 exclude 한 뒤 gateway 고유 필터 체인과 `GatewayPlatformSecurityConfiguration`이 platform runtime surface를 조립합니다.

중요한 기준:

| 질문 | 답 |
| --- | --- |
| 지금도 순수 Java라서 platform-security를 못 쓰는 상태인가 | 아닙니다. Spring Boot로 전환되어 있고, platform-security policy engine도 실제 요청 경로에서 사용합니다. |
| Gateway 인증 정책은 어디서 적용되는가 | credential 검증과 정책 판정은 `GatewayPlatformSecurityWebFilter`에서 수행됩니다. |
| 왜 WebFlux security chain은 `permitAll`인가 | Spring Security 기본 인증이 `/health`, 공개 API, 프록시 요청을 먼저 차단하지 않게 하기 위해서입니다. Gateway 정책은 별도 필터에서 수행합니다. |
| 현재 2계층 플랫폼을 실제로 쓰는 부분은 무엇인가 | `platform-security`는 `HybridSecurityRuntime`, boundary/IP/rate-limit/admin authz policy 평가에, `platform-security-governance-bridge`는 security audit publish에, `platform-governance`는 internal audit recorder와 `AuditSink` delivery에 사용합니다. |
| `jakarta.servlet-api`가 왜 들어갔는가 | 현재 `platform-security-starter` 쪽 auto-configuration이 servlet 타입을 참조하므로, WebFlux 앱에서도 클래스 로딩이 실패하지 않도록 런타임 classpath에 둡니다. |

현재 상태를 정확히 표현하면 다음과 같습니다.

```txt
security:
  GatewayPlatformSecurityWebFilter에서 credential 검증
  platform-security policy service에서 boundary/IP/rate-limit/admin authz 평가
  GatewayPolicyFilter에서 허용 요청만 실행

governance:
  platform-governance audit recorder 사용

platform-security-governance-bridge:
  SecurityAuditPublisher로 실제 연동
  security verdict를 governance audit으로 발행

operational audit:
  GatewayOperationalAuditPort로 upstream/proxy audit 기록
```

전환 중 문제가 생기면 먼저 아래를 확인합니다.

- `/health`가 401이면 `GatewayWebSecurityConfiguration`이 로딩되는지 확인합니다.
- platform 기본 filter가 끼어드는 것처럼 보이면 `GatewayApplication`의 auto-config exclude 설정이 유지되는지 확인합니다.
- `jakarta/servlet/Filter` 클래스 오류가 나면 `jakarta.servlet:jakarta.servlet-api` 의존성이 빠졌는지 확인합니다.
- 인증이 모두 우회되는 것처럼 보이면 `GatewayPlatformSecurityWebFilter`가 먼저 실행되는지, `GatewayPolicyFilter`가 인증을 다시 하지 않는지 확인합니다.
- 관리자 경로가 모두 403이면 `AUTHZ_ADMIN_VERIFY_URL`, `GATEWAY_INTERNAL_REQUEST_SECRET`, `AUTHZ_INTERNAL_JWT_*`를 먼저 확인합니다.

## contract lock이 안 맞음

`contract.lock.yml`의 commit은 이 repo가 따르는 service-contract commit입니다. API path, request, response, header, status, auth 정책이 바뀌면 service-contract를 먼저 수정하고 lock commit을 갱신해야 합니다.
