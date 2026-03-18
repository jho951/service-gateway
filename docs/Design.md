# Gateway Design

## 구성

### 다음 3개로 구성합니다.

- Auth Service
- User Service
- Block Service

### 추후 추가 요소
- Permission Service

**ELK는 Gateway의 라우팅 대상 비즈니스 서비스가 아니라 observability 인프라**입니다.

즉 ELK는 Gateway 뒤의 업스트림 서비스가 아니라, Gateway 및 각 서비스의 로그/메트릭/트레이스를 수집하는 sink이다.

 **Edge Gateway**

- 외부 단일 진입점
- 라우팅
- 인증 상태 판별
- 사용자 컨텍스트 전달
- 관리자/API 보안 정책 적용
- observability/logging
- rate limit
- IP guard

---

## System Context

```text
Client
  ↓
API Gateway
  ├ Auth Service
  ├ User Service
  ├ Block Service
  └ Permission Service

Gateway / Services
  └ logs, metrics, traces -> ELK
```

Gateway는 모든 외부 요청의 1차 관문이며, 내부 서비스는 원칙적으로 Gateway 뒤에 위치한다.

---

## Design Goals

1. 외부 요청의 단일 진입점 제공
2. Auth Service 중심의 SSO 구조와 연동
3. 세션 기반 외부 인증과 내부 서비스 인증 컨텍스트를 분리
4. 고빈도 보호 API 요청에서 중앙 인증 병목 최소화
5. 관리자 경로와 일반 사용자 경로를 분리된 정책으로 보호
6. audit-log, rate limiter 같은 공통 모듈을 붙이기 쉬운 구조 확보
7. Trusted Header 기반 내부 전달 구조를 안전하게 운영할 수 있는 신뢰 경계 명시
8. internal route를 gateway 정책과 네트워크 토폴로지 양쪽에서 보호
9. 향후 internal JWT 또는 서명 헤더 기반 stronger trust model로 확장 가능하도록 설계

---

## Non Goals

다음은 Gateway의 책임이 아니다.

- GitHub OAuth2 provider 연동 세부 구현
- 사용자 원본 정보 저장
- 블록 비즈니스 로직 처리
- 최종 권한 정책 저장 및 관리
- 블록 데이터 직접 수정
- ELK 인덱스 관리 및 분석 파이프라인 운영

즉 Gateway는 **인증 소유 서비스**가 아니라, 인증 상태를 확인하고 안전하게 전달하는 **오케스트레이션 레이어**이다.

---

## Core Responsibilities

## 1. Routing

Gateway는 경로별로 요청을 적절한 서비스로 전달한다.

### Route Map

```text
/auth/**              -> Auth Service
/users/**             -> User Service
/blocks/**            -> Block Service
/permissions/**       -> Permission Service

/admin/users/**       -> User Service
/admin/blocks/**      -> Block Service
/admin/permissions/** -> Permission Service
```

### Notes

- `/admin/**`는 단순한 정책 분류가 아니라 **실제 업스트림 타깃 매핑 계약**도 포함한다.
- Admin 경로는 하나의 별도 “Admin Backend”로 몰지 않고, 현재는 각 도메인 서비스의 admin-capable API로 라우팅한다.
- ELK는 업스트림 라우팅 대상이 아니다.

---

## 2. Authentication Orchestration

Gateway는 보호 경로에 대해 다음을 수행한다.

1. 요청 경로가 인증이 필요한지 확인
2. 세션 쿠키 또는 인증 컨텍스트 확인
3. Auth Service에 세션 검증 요청
4. 검증 성공 시 사용자 컨텍스트 생성
5. 내부 서비스로 사용자 정보 전달

### 구조

```text
External Auth Source = Auth Service
Request Gatekeeper   = API Gateway
Business Execution   = Downstream Services
```

---

## 3. User Context Propagation

Gateway는 인증 성공 후 내부 서비스가 사용할 사용자 컨텍스트를 전달한다.  
현재는 **Trusted Header 방식**을 사용한다.

### Trusted Header Example

```text
X-User-Id: user-123
X-User-Role: USER
X-Session-Id: session-abc
X-Request-Id: req-xyz
X-Correlation-Id: corr-xyz
```

### Mandatory Header Sanitization Rule

외부 클라이언트가 동일한 사용자 컨텍스트 헤더를 직접 넣더라도 **절대 신뢰하지 않는다.**

예:

```text
Client가 X-User-Id: admin 을 넣고 요청
→ Gateway는 외부 입력 헤더를 제거
→ 인증 성공 후 Gateway가 신뢰 가능한 값으로 재주입
```

즉 다음 규칙을 강제한다.

1. Gateway는 외부 요청에서 들어온 user-context 계열 헤더를 먼저 제거한다.
2. 인증 성공 후 Gateway가 내부 표준 헤더를 다시 주입한다.
3. 내부 서비스는 Gateway가 재주입한 헤더만 신뢰한다.

---

## 4. Policy Enforcement

Gateway는 다음 정책을 앞단에서 집행한다.

- 인증 필요 경로 보호
- 관리자 경로 추가 보호
- internal API 외부 차단
- CORS / body size / timeout / rate limit 정책
- ip-guard
- request id 및 correlation id 주입
- public/protected/admin/internal 4계층 라우트 정책 적용

---

## 5. Observability

Gateway는 다음 관측성 기능을 제공한다.

- access log
- request id 발급
- upstream latency 측정
- auth validation 결과 로깅
- 4xx / 5xx metrics
- admin access audit-ready log
- tracing header 전달

---

## Authentication Model

본 시스템의 인증 모델은 Hybrid 구조다.

### External User Authentication

브라우저 사용자는 SSO 세션으로 인증한다.

```text
Browser -> Session Cookie -> Gateway -> Auth Service validation
```

### Internal Service Authentication

Gateway는 세션 검증 결과를 기반으로 내부 서비스용 인증 컨텍스트를 만든다.

```text
Gateway -> Trusted Headers -> Downstream Services
```

### Principle

```text
외부 사용자 인증은 Session 중심
내부 서비스 인증 전달은 Header 중심
장기적으로는 Header/JWT 혼합으로 확장 가능
```

---

## Why Hybrid?

세션만으로 모든 요청을 처리하면 다음 문제가 발생한다.

- 고빈도 API에서 Auth Service 병목 가능
- 내부 서비스가 쿠키 기반 인증을 직접 해석해야 함
- 서비스 간 호출 확장성이 낮음

JWT만으로 모든 것을 처리하면 다음 문제가 있다.

- SSO 로그아웃/강제 로그아웃 제어가 어려움
- 관리자 보안 정책 반영이 복잡함
- 브라우저 로그인 UX 제어가 불편해질 수 있음

따라서 현재 구조에서는 다음 방식이 가장 적절하다.

```text
외부는 Session
내부 전달은 Trusted Header
장기적으로는 서명 헤더 또는 Internal JWT 확장
```

---

## Authentication Flow

## Login Flow

```text
User
  ↓
Intro / Login Page
  ↓
API Gateway
  ↓
Auth Service (/auth/login/github)
  ↓
GitHub OAuth2
  ↓
Auth Service Callback
  ├ create session
  ├ issue session cookie
  └ establish SSO login state
  ↓
Client Logged In
```

---

## Protected API Request Flow

```text
Client
  ↓
API Gateway
  ├ check route policy
  ├ read session cookie
  ↓
Auth Service (/auth/internal/session/validate)
  ↓
Gateway
  ├ remove untrusted external auth headers
  ├ create trusted user context
  ├ inject internal headers
  ↓
Block / Permission / User Service
```

---

## Admin Request Flow

```text
Admin Client
  ↓
API Gateway
  ├ validate session
  ├ classify route = /admin/**
  ├ check admin role
  ├ verify permission with Permission Service
  ├ apply stricter security policy
  ↓
Admin-capable upstream API
```

---

## Route Classification

Gateway는 경로를 최소 4가지 클래스로 구분한다.

## 1. Public Routes

인증 없이 접근 가능

```text
/health
/auth/login/github
/auth/oauth/github/callback
/public/**
```

## 2. Protected User Routes

일반 로그인 사용자 필요

```text
/users/me
/blocks/**
/permissions/**
```

## 3. Admin Routes

관리자 권한과 강화된 정책 필요

```text
/admin/**
```

## 4. Internal Routes

외부 접근 금지

```text
/auth/internal/**
/internal/**
```

---

## Recommended Route Policy Matrix

| Route Pattern                 | Auth Required | Extra Check | Upstream           | Notes                  |
|-------------------------------|---:|---|--------------------|------------------------|
| `/health`                     | No | None | gateway local      | liveness/readiness     |
| `/auth/login/github`          | No | Rate limit | Auth Service       | login start            |
| `/auth/oauth/github/callback` | No | callback validation | Auth Service       | oauth callback         |
| `/auth/session`               | Yes/Optional | session check | Auth Service       | current session status |
| `/users/me`                   | Yes | None | User Service       | current user           |
| `/blocks/**`                  | Yes | trusted user context | Block Service      | user block APIs        |
| `/permissions/**`             | Yes | downstream permission logic | Permission Service | permission APIs        |
| `/admin/users/**`             | Yes | admin role + permission verify | User Service       | admin user APIs        |
| `/admin/blocks/**`            | Yes | admin role + permission verify | Block Service      | admin block APIs       |
| `/admin/permissions/**`       | Yes | admin role + permission verify | Permission Service | admin permission APIs  |
| `/auth/internal/**`           | No external access | internal allowlist | Auth Service       | service-only           |

---

## Gateway Trust Model

내부 서비스는 다음 원칙을 따른다.

### Rule 1
외부 클라이언트가 직접 넣은 인증 헤더는 신뢰하지 않는다.

### Rule 2
Gateway가 주입한 내부 헤더만 신뢰한다.

### Rule 3
내부 서비스는 세션 쿠키를 직접 해석하지 않는다.

### Rule 4
서비스가 외부에 직접 노출되지 않도록 네트워크 레벨에서도 차단한다.

### Rule 5
Gateway 출발 요청만 신뢰 가능한 요청으로 본다.

---

## Internal Trust Boundary Requirements

단순히 “Gateway 헤더를 신뢰한다”만으로는 부족하다.  
아래 중 최소 하나 이상을 인프라 수준에서 보장해야 한다.

- internal network only
- trusted proxy only
- mTLS
- private subnet restriction
- security group / firewall 제한
- ingress rule 차단
- service discovery scope 제한

### Mandatory Statement

```text
Internal routes and trusted headers are protected both by gateway policy and network topology.
```

---

## Security Design

## 1. Session Validation

초기에는 Gateway가 Auth Service validation API를 호출한다.

```text
POST /auth/internal/session/validate
```

응답 예시:

```json
{
  "authenticated": true,
  "userId": "user-123",
  "role": "USER",
  "sessionId": "session-abc"
}
```

---

## 2. Trusted Header Hardening

현재는 Trusted Header 방식을 사용하지만, 민감 경로에 대해서는 stronger trust model이 필요할 수 있다.

### Near-Term Rule
- 외부 헤더 제거 후 재주입
- 내부망에서만 신뢰
- admin 경로에는 stricter verification 적용

### Long-Term Option
- 서명 헤더(signed headers)
- internal JWT
- gateway-issued short-lived auth envelope

특히 Admin 또는 민감 경로는 단순 헤더보다 더 강한 신뢰 모델이 바람직하다.

---

## 3. Admin Security Policy

관리자 경로는 일반 사용자 경로보다 더 강한 정책을 적용한다.

### Admin Source of Truth

현재 권장 정책:

- **관리자 식별의 1차 기준**: `User Service.role`
- **실제 관리자 작업 허용의 최종 기준**: `Permission Service`

즉,

```text
User.role = coarse-grained admin eligibility
Permission Service = fine-grained admin authorization
```

### Mandatory Admin Checks

`/admin/**`에 대해서는 다음을 **필수**로 적용한다.

1. every-request session validation
2. admin role check
3. Permission Service authorization check
4. audit-ready logging
5. ip-guard allowlist

### Optional Admin Controls

다음은 환경에 따라 선택 적용한다.

- 더 짧은 세션 TTL
- step-up re-authentication
- office/VPN IP only
- device trust
- no-cache policy for admin auth context

### Current Decision

현 시점 권장안은 다음과 같다.

- `/admin/**`는 **매 요청마다 session validate**
- `/admin/**`는 **매 요청마다 Permission Service 확인**
- 일반 사용자 세션과 admin 전용 세션을 분리하지는 않음
- 단, admin access에 대해서는 stricter route policy와 audit logging을 적용
- 운영 환경에서는 가능하면 office/VPN allowlist 적용

---

## 4. Internal API Protection

다음과 같은 경로는 외부에서 직접 접근하면 안 된다.

```text
/auth/internal/**
/internal/**
```

이는 Gateway route rule만으로 보호하지 않는다.  
반드시 네트워크 토폴로지에서도 보호한다.

### Required Controls

- internal LB only
- private subnet only
- SG / firewall 제한
- ingress 차단
- service discovery scope 제한

### Mandatory Statement

```text
Internal routes are protected both by gateway policy and network topology.
```

---

## 5. HTTPS / Secure Transport

모든 외부 요청은 HTTPS를 사용해야 한다.  
세션 쿠키는 Secure / HttpOnly / SameSite 정책을 준수해야 한다.

---

## 6. IP Guard Integration

ip-guard는 우선적으로 Gateway에 적용한다.

### Why Gateway First?

- 외부 요청의 1차 차단 가능
- 내부 서비스 보호
- 공통 정책 관리 용이
- 관리자/API 경로별 allowlist 분리 가능

### Additional Defense-in-Depth

민감 서비스에는 추가 적용할 수 있다.

- Auth Service
- Admin-capable APIs
- Permission Service

---

## Error Handling Model

Gateway는 공통 에러 포맷을 가져야 한다.

고정된 에러 코드 계약은 [Error-Codes.md](/Users/jhons/Downloads/BE/Api-gateway-server/docs/Error-Codes.md)를 기준으로 관리한다.

### Example: 401

```json
{
  "httpStatus": 401,
  "success": false,
  "message": "인증이 필요합니다.",
  "code": 9101,
  "data": null
}
```

### Example: 403

```json
{
  "httpStatus": 403,
  "success": false,
  "message": "접근이 허용되지 않습니다.",
  "code": 9102,
  "data": null
}
```

### Example: 504 / Upstream Timeout

```json
{
  "httpStatus": 504,
  "success": false,
  "message": "업스트림 응답 시간이 초과되었습니다.",
  "code": 9105,
  "data": null
}
```

---

## Operational Concerns

## 1. Timeout / Retry Policy

모든 upstream 호출에 대해 timeout을 명확히 설정해야 한다.

- Auth validation timeout
- user/block/permission upstream timeout
- admin path stricter timeout policy 가능

Retry는 읽기 요청과 멱등 요청에만 제한적으로 적용한다.

---

## 2. Request Correlation

Gateway는 요청마다 고유 request id를 생성하고 모든 downstream에 전달한다.

### Recommended Headers

```text
X-Request-Id
X-Correlation-Id
```

---

## 3. Logging

### 최소 로그 항목 예시

- timestamp
- requestId
- path
- method
- client ip
- upstream service
- response status
- latency
- auth result
- userId (가능한 경우)
- admin 여부

---

## 4. Metrics

### 추천 지표

- requests_total by route
- auth_validation_failures_total
- upstream_timeout_total
- admin_access_total
- blocked_by_ipguard_total
- response_latency_ms

---

## 5. Environment Configuration

로컬/dev/staging/prod에서 route config를 외부화한다.

### 예시

```yaml
routes:
  auth: http://auth-service:8080
  user: http://user-service:8081
  block: http://block-service:8082
  permission: http://permission-service:8083
```

---

## High-Frequency Protected API Optimization

현재 서비스 목록에는 **Block Service가 포함**되므로, 고빈도 보호 API 최적화 원칙을 명시한다.

### Optimization Targets

- 세션 검증 API 호출 수 감소
- Auth Service 병목 완화
- 고빈도 protected route의 인증 처리 비용 절감

### Current Recommendation

- 일반 protected route에 대해 **짧은 TTL의 auth validation cache**를 둘 수 있다
- 권장 TTL 예: `10~30초`
- admin route는 캐시하지 않거나 매우 보수적으로만 캐시한다

### Cache Policy Example

```text
Protected user routes -> short auth cache allowed
Admin routes          -> no cache or every-request validate
Internal routes       -> not externally reachable
```

### Notes

고빈도 입력/동기화 API에 대해서는 다음을 별도 설계한다.

- auth cache TTL
- throttling
- sync path vs 일반 CRUD path 분리
- low-latency route policy

---

## Evolution Roadmap

Gateway는 한 번에 완성하지 않고 단계적으로 발전시킨다.

## Phase 1. Reverse Proxy Gateway

- 기본 라우팅
- health check
- request id
- access log
- timeout

## Phase 2. Auth-Aware Gateway

- public/protected/internal route 구분
- session cookie 읽기
- Auth Service session validate 연동
- user context header 주입
- 외부 동일 헤더 제거 후 재주입

## Phase 3. Policy Gateway

- admin route 별도 정책
- internal API 외부 차단
- ip-guard 적용
- rate limiting 적용
- 공통 에러 모델 정착
- internal trust boundary 명시

## Phase 4. Production Gateway

- auth validation cache
- stronger observability
- circuit breaker / resilience
- signed header or internal JWT
- zero-trust style hardening

---

## Recommended Package / Module Structure

예시 구조:

```text
gateway
├─ src/main/java/...
│  ├─ config
│  │  ├─ RouteConfig
│  │  ├─ SecurityConfig
│  │  └─ CorsConfig
│  ├─ filter
│  │  ├─ RequestIdFilter
│  │  ├─ AuthValidationFilter
│  │  ├─ HeaderSanitizationFilter
│  │  ├─ AdminPolicyFilter
│  │  ├─ InternalRouteBlockFilter
│  │  └─ IpGuardFilterAdapter
│  ├─ auth
│  │  ├─ AuthValidationClient
│  │  ├─ AuthContext
│  │  └─ AuthContextInjector
│  ├─ route
│  │  ├─ RoutePolicy
│  │  ├─ RouteClassifier
│  │  └─ RouteTargets
│  ├─ trust
│  │  ├─ TrustedHeaderPolicy
│  │  ├─ InternalNetworkPolicy
│  │  └─ GatewayTrustValidator
│  ├─ error
│  │  ├─ GatewayErrorCode
│  │  ├─ GatewayExceptionHandler
│  │  └─ ErrorResponse
│  └─ observability
│     ├─ AccessLogService
│     ├─ MetricsPublisher
│     └─ TraceHeaderSupport
└─ src/main/resources
   ├─ application.yml
   └─ route-policy.yml
```

---

## Design Principles Summary

### Principle 1
Gateway는 **단순 프록시가 아니라 외부 진입 정책 레이어**다.

### Principle 2
실제 로그인/OAuth2/세션 발급의 소유자는 Auth Service다.

### Principle 3
Gateway는 세션을 검증하고 내부 서비스용 사용자 컨텍스트를 만든다.

### Principle 4
내부 서비스는 세션 쿠키를 직접 해석하지 않는다.

### Principle 5
외부에서 들어온 동일 user-context 헤더는 제거 후 Gateway가 재주입한다.

### Principle 6
내부 서비스는 Gateway 출발 요청만 신뢰한다.

### Principle 7
관리자 경로와 일반 사용자 경로는 다른 강도의 정책을 가진다.

### Principle 8
ip-guard, rate limit, observability는 Gateway에서 먼저 적용한다.

### Principle 9
internal route와 trusted header는 gateway rule과 network topology 양쪽에서 보호한다.

---

## Final Summary

```text
Gateway = External Entry Point + Authentication Orchestrator + Security Policy Enforcer
```

인증 구조는 다음과 같다.

```text
External User -> Session
Gateway Internal Context -> Trusted Headers
SSO Source of Truth -> Auth Service
```

그리고 전체 흐름은 다음과 같다.

```text
Client
  ↓
API Gateway
  ↓
Auth validation / route policy / trusted header injection
  ↓
Auth / User / Block / Permission Services
```

이 구조를 기준으로 Gateway를 설계하면, 현재의 SSO + Session/JWT Hybrid 인증 모델과 MSA 구조를 안정적으로 수용할 수 있다.
