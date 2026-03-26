FROM gradle:8.14.3-jdk17 AS builder

WORKDIR /workspace

COPY gradle gradle
COPY gradlew gradlew
COPY build.gradle settings.gradle gradle.properties ./
COPY src src

RUN chmod +x gradlew
RUN ./gradlew --no-daemon clean installDist

FROM eclipse-temurin:17-jre-jammy

WORKDIR /app

COPY --from=builder /workspace/build/install/Api-gateway-server /app/
RUN touch /app/.env.local /app/.env.prod

EXPOSE 8080

ENV GATEWAY_BIND=0.0.0.0
ENV GATEWAY_PORT=8080

CMD ["/app/bin/Api-gateway-server"]
