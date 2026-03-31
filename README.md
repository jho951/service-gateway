# Api Gateway Server

## Contract Sync

- 이 레포의 계약 동기화 기준 파일은 루트 [CONTRACT_SYNC.md](CONTRACT_SYNC.md) 이다.
- 계약 영향 변경이 있으면 `CONTRACT_SYNC.md`를 먼저 갱신하고, 그 다음 구현을 맞춘다.
- 참조 계약 문서는 `contract` 레포의 Gateway 관련 문서를 따른다.
- 변경 시 `contract` 레포의 최신 commit SHA와 동기화 날짜를 반드시 기록한다.

## 기준
SoT 브랜치: `main`

## 요구 사항

- Java 17
- Docker
- Docker Compose

## 실행

```bash
// 개발
bash scripts/run.docker.sh dev
```

```bash
// 운영
bash scripts/run.docker.sh prod
```

## [문서](https://github.com/jho951/Api-gateway-server/wiki)

