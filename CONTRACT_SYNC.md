# CONTRACT_SYNC.md

## Repository
- Repo: `https://github.com/jho951/Api-gateway-server`
- Branch: `main`
- Role: `backend-service`

## Contract Source
- Contract Repo: `https://github.com/jho951/contract`
- Contract Commit SHA: `<contract-sha>`
- Latest Sync Date: `<YYYY-MM-DD>`

## Referenced Docs
- `README.md`
- `contracts/gateway/README.md`
- `contracts/gateway/responsibility.md`
- `contracts/gateway/auth-proxy.md`
- `contracts/gateway/auth.md`
- `contracts/gateway/security.md`
- `contracts/gateway/cache.md`
- `contracts/gateway/response.md`
- `contracts/gateway/env.md`
- `contracts/gateway/errors.md`
- `contracts/gateway/execution.md`
- `contracts/routing.md`
- `contracts/headers.md`
- `contracts/security.md`
- `contracts/auth-channel-policy.md`
- `contracts/openapi/gateway-edge.v1.yaml`

## Impact Scope
- Contract Areas:
    - `routing`
    - `headers`
    - `security`
    - `auth`
    - `cache`
    - `response`
    - `env`
    - `errors`
    - `openapi`
- Affected Flows:
    - `브라우저 인증`
    - `비브라우저 인증`
    - `Gateway 인증 프록시`
    - `내부 헤더 재주입`
    - `health/ready`
    - `INTERNAL secret`
    - `L1/L2 session cache`
    - `Gateway passthrough response`

## Validation
- Commands:
    - `git diff --check`
    - `./gradlew test`
    - `curl -i http://localhost:8080/v1/health`
    - `curl -i http://localhost:8080/v1/ready`
- Result:
    - `<pass/fail summary>`

## Sync Log
| Date | Contract SHA | Areas | Notes |
  |---|---|---|---|
| `<YYYY-MM-DD>` | `<contract-sha>` | `<routing, headers, ...>` | `<short note>` |
