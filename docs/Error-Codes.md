# Error Codes

**API Gateway의 공통 오류 응답입니다.**

## 응답구조

```json
{
  "httpStatus": 401,
  "success": false,
  "message": "인증이 필요합니다.",
  "code": 9101,
  "data": null
}
```

### 필드:

- `httpStatus`: HTTP 상태 코드
- `success`: 항상 `false`
- `message`: 사용자/클라이언트가 해석할 수 있는 메시지
- `code`: 게이트웨이 비즈니스 오류 코드
- `data`: 오류 응답에서는 항상 `null`

## Fixed Error Codes

| Enum | HTTP | Code | Message | Meaning |
|---|---:|---:|---|---|
| `INVALID_REQUEST` | 400 | 9015 | 잘못된 요청입니다. | 게이트웨이 입력 형식이 잘못된 경우 |
| `VALIDATION_ERROR` | 400 | 9016 | 요청 필드 유효성 검사에 실패했습니다. | 요청 검증 실패 |
| `METHOD_NOT_ALLOWED` | 405 | 9017 | 허용되지 않은 HTTP 메서드입니다. | 지원하지 않는 HTTP 메서드 |
| `NOT_FOUND_URL` | 404 | 9002 | 요청하신 URL을 찾을 수 없습니다. | 매핑된 gateway route가 없음 |
| `UNAUTHORIZED` | 401 | 9101 | 인증이 필요합니다. | protected/admin 경로에서 인증 실패 |
| `FORBIDDEN` | 403 | 9102 | 접근이 허용되지 않습니다. | internal 경로 접근, IP 차단, admin 권한 부족 |
| `TOO_MANY_REQUESTS` | 429 | 9103 | 요청이 너무 많습니다. | 로그인 시도 rate limit 초과 |
| `PAYLOAD_TOO_LARGE` | 413 | 9104 | 요청 본문이 허용 크기를 초과했습니다. | body size 제한 초과 |
| `UPSTREAM_TIMEOUT` | 504 | 9105 | 업스트림 응답 시간이 초과되었습니다. | Auth/Permission/Upstream timeout |
| `UPSTREAM_FAILURE` | 502 | 9106 | 업스트림 호출에 실패했습니다. | 업스트림 I/O 실패 또는 비정상 호출 실패 |
| `FAIL` | 400 | 9999 | 요청 응답 실패, 관리자에게 문의해주세요. | 분류되지 않은 gateway 내부 예외 |

## Mapping Rules

- `UNAUTHORIZED`: Auth Service 검증 결과가 인증 실패일 때 사용한다.
- `FORBIDDEN`: 인증은 되었지만 접근 권한이 없거나, internal/admin/IP 정책에 의해 차단될 때 사용한다.
- `UPSTREAM_TIMEOUT`: `InterruptedException` 또는 타임아웃 성격의 업스트림 실패에 사용한다.
- `UPSTREAM_FAILURE`: 일반적인 업스트림 I/O 실패에 사용한다.
- `FAIL`: 위 규칙으로 분류되지 않은 예외에 사용한다.

## Source Of Truth

운영 계약의 최종 기준은 코드의 [ErrorCode.java](/Users/jhons/Downloads/BE/Api-gateway-server/src/main/java/com/gateway/code/ErrorCode.java) 입니다.

문서와 코드가 다르면 코드를 수정하기 전에 이 문서를 먼저 갱신해야 한다.
