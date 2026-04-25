# EC2 Deploy Assets

이 디렉터리는 EC2에 앱 소스를 clone 하지 않고, 배포용 파일만 올리는 운영 방식을 위한 최소 산출물입니다.

## 서버에 두는 파일

- `docker-compose.yml`
- `.env.production`
- `nginx/gateway-service.conf.example`

## 운영 원칙

- EC2에는 `gateway-service` 앱 소스를 clone 하지 않습니다.
- EC2는 Docker image를 pull 받아 실행하는 서버입니다.
- Gateway는 기본적으로 `127.0.0.1:8080` 으로만 바인딩하고, 호스트 Nginx가 앞단에서 프록시합니다.

## 배포 순서

1. EC2에 이 디렉터리의 파일만 복사합니다.
2. `.env.production.example` 을 `.env.production` 으로 복사하고 값을 채웁니다.
3. `nginx/gateway-service.conf.example` 를 실제 도메인에 맞게 조정합니다.
4. 아래 명령으로 이미지를 갱신합니다.

```bash
docker compose --env-file .env.production pull
docker compose --env-file .env.production up -d
```
