package com.gateway.auth;

import com.gateway.contract.internal.path.ServicePaths;
import com.gateway.contract.internal.header.TraceHeaders;
import com.gateway.contract.internal.header.ServiceHeaders;
import com.gateway.http.Jsons;

import java.time.Duration;
import java.io.IOException;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 인증 서비스(Auth Service)와 통신하여
 * 세션의 유효성을 검증하는 HTTP 클라이언트입니다.
 * <p>
 * 외부 JSON 라이브러리 의존성을 제거하기 위해 정규표현식을 사용하여 응답을 파싱하며,
 * 게이트웨이의 성능을 위해 비동기 처리에 적합한 Java 표준 HttpClient를 사용합니다.
 * </p>
 */
public final class AuthServiceClient {
    // "authenticated": true | false (인증 여부)
    private static final Pattern BOOLEAN_FIELD = Pattern.compile("\"authenticated\"\\s*:\\s*(true|false)");
    // "userId": jhonui, 10045 (사용자 유일 키로 핵심)
    private static final Pattern USER_ID_FIELD = Pattern.compile("\"userId\"\\s*:\\s*\"([^\"]+)\"");
    // "role": 문자열 (사용자 등급)
    private static final Pattern ROLE_FIELD = Pattern.compile("\"role\"\\s*:\\s*\"([^\"]+)\"");
    // "status": ACTIVE (사용자 상태)
    private static final Pattern STATUS_FIELD = Pattern.compile("\"status\"\\s*:\\s*\"([^\"]+)\"");
    // "sessionId": random_string_... (사용자 고유 연결 번호)
    private static final Pattern SESSION_ID_FIELD = Pattern.compile("\"sessionId\"\\s*:\\s*\"([^\"]+)\"");
    // auth-service 표준 토큰 응답 필드
    private static final Pattern ACCESS_TOKEN_FIELD = Pattern.compile("\"accessToken\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern ACCESS_TOKEN_SNAKE_FIELD = Pattern.compile("\"access_token\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern TOKEN_FIELD = Pattern.compile("\"token\"\\s*:\\s*\"([^\"]+)\"");
    // auth-service와 통신하는 실행기
    private final HttpClient client;
    // 너무 오래 걸리면 끊는 제한값
    private final Duration timeout;

    /**
     * 응답 헤더에서 특정 이름을 가진 첫 번째 값을 추출합니다.
     * @param response HTTP 응답 객체
     * @param headerName 찾고자 하는 헤더 이름
     * @return 헤더 값 (없을 경우 null)
     */
    private String firstHeader(HttpResponse<?> response, String headerName) {
        Optional<String> header = response.headers().firstValue(headerName);
        return header.orElse(null);
    }

    /**
     * JSON 응답 바디에서 "authenticated" 필드의 불리언 값을 확인합니다.
     * @param responseBody JSON 문자열
     * @return 인증 여부 (true | false)
     */
    private boolean isAuthenticated(String responseBody) {
        Matcher matcher = BOOLEAN_FIELD.matcher(responseBody);
        return matcher.find() && Boolean.parseBoolean(matcher.group(1));
    }

    /**
     * JSON 응답 바디에서 role, status, sessionId, userId 중 필드 값을 추출합니다.
     * @param responseBody JSON 문자열
     * @param pattern 추출할 필드에 대한 정규표현식 패턴
     * @return 추출된 문자열 (매칭 실패 시 null)
     */
    private String firstJsonField(String responseBody, Pattern pattern) {
        Matcher matcher = pattern.matcher(responseBody);
        if (!matcher.find()) return null;
        return matcher.group(1);
    }

    /**
     * 생성자 (생성자 호출로 직접 생성이 불가해 Builder 패턴 적용)
     * @param timeout 연결 및 요청 타임아웃 설정 시간
     */
    public AuthServiceClient(Duration timeout) {
        this.client = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        this.timeout = timeout;
    }

    /**
     *  인증 서비스(Auth Service)에 세션 검증 요청을 보내고 결과를 AuthResult로 반환합니다.
     * <p>
     * 1. 인증 서비스의 검증 API 호출 (/auth/session)<br>
     * 2. 응답 바디 또는 헤더에서 사용자 정보(ID, Role, SessionID) 추출<br>
     * 3. HTTP 상태 코드와 인증 필드를 종합하여 최종 결과 생성
     * </p>
     * @param authServiceBaseUri 인증 서비스의 베이스 URI
     * @param authorizationHeader 클라이언트가 보낸 Authorization 헤더 (Bearer 토큰 등)
     * @param requestId 요청 추적을 위한 고유 ID
     * @param correlationId 연관 관계 추적을 위한 ID
     * @return 인증 성공 여부 및 사용자 정보가 담긴 {@link AuthResult}
     * @throws IOException 네트워크 오류 발생 시
     * @throws InterruptedException 요청 중단 시
     */
    public AuthResult validateSession(
            URI authServiceBaseUri,
            String authorizationHeader,
            String cookieHeader,
            String requestId,
            String correlationId
    ) throws IOException, InterruptedException {
        URI targetUri = authServiceBaseUri.resolve(ServicePaths.Auth.SESSION_VALIDATE);

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(targetUri)
                .timeout(timeout)
                .POST(HttpRequest.BodyPublishers.noBody())
                .header(TraceHeaders.REQUEST_ID, requestId)
                .header(TraceHeaders.CORRELATION_ID, correlationId);
        if (authorizationHeader != null && !authorizationHeader.isBlank()) {
            requestBuilder.header("Authorization", authorizationHeader);
        }
        if (cookieHeader != null && !cookieHeader.isBlank()) {
            requestBuilder.header("Cookie", cookieHeader);
        }
        HttpRequest request = requestBuilder.build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        String responseBody = response.body() == null ? "" : response.body();
        String userId = firstJsonField(responseBody, USER_ID_FIELD);
        if (userId == null || userId.isBlank()) {
            userId = firstHeader(response, ServiceHeaders.Trusted.USER_ID);
        }
        String role = firstJsonField(responseBody, ROLE_FIELD);
        if (role == null || role.isBlank()) {
            role = firstHeader(response, ServiceHeaders.Trusted.USER_ROLE);
        }
        String status = firstJsonField(responseBody, STATUS_FIELD);
        String sessionId = firstJsonField(responseBody, SESSION_ID_FIELD);
        if (sessionId == null || sessionId.isBlank()) {
            sessionId = firstHeader(response, ServiceHeaders.Trusted.SESSION_ID);
        }

        boolean authenticated = response.statusCode() == 200
                && isAuthenticated(responseBody)
                && userId != null
                && !userId.isBlank();

        return new AuthResult(response.statusCode(), authenticated, userId, role, status, sessionId);
    }

    /**
     * Basic 인증 정보를 auth-service 로그인 API로 교환해 표준 Bearer 토큰 헤더로 정규화합니다.
     *
     * @param authServiceBaseUri 인증 서비스의 베이스 URI
     * @param authorizationHeader 클라이언트가 보낸 Basic Authorization 헤더
     * @param requestId 요청 추적을 위한 고유 ID
     * @param correlationId 연관 관계 추적을 위한 ID
     * @return 교환에 성공한 Bearer Authorization 헤더, 실패 시 null
     * @throws IOException 네트워크 오류 발생 시
     * @throws InterruptedException 요청 중단 시
     */
    public String exchangeBasicForBearer(
            URI authServiceBaseUri,
            String authorizationHeader,
            String requestId,
            String correlationId
    ) throws IOException, InterruptedException {
        BasicCredentials credentials = parseBasicCredentials(authorizationHeader);
        if (credentials == null) {
            return null;
        }

        URI targetUri = authServiceBaseUri.resolve(ServicePaths.Auth.LOGIN);
        String requestBody = Jsons.toJson(Map.of(
                "username", credentials.username(),
                "password", credentials.password()
        ));

        HttpRequest request = HttpRequest.newBuilder(targetUri)
                .timeout(timeout)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody, StandardCharsets.UTF_8))
                .header("Content-Type", "application/json")
                .header(TraceHeaders.REQUEST_ID, requestId)
                .header(TraceHeaders.CORRELATION_ID, correlationId)
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            return null;
        }

        String responseBody = response.body() == null ? "" : response.body();
        String accessToken = firstJsonField(responseBody, ACCESS_TOKEN_FIELD);
        if (accessToken == null || accessToken.isBlank()) {
            accessToken = firstJsonField(responseBody, ACCESS_TOKEN_SNAKE_FIELD);
        }
        if (accessToken == null || accessToken.isBlank()) {
            accessToken = firstJsonField(responseBody, TOKEN_FIELD);
        }
        if (accessToken == null || accessToken.isBlank()) {
            accessToken = firstHeader(response, "Authorization");
        }
        return normalizeBearer(accessToken);
    }

    private static BasicCredentials parseBasicCredentials(String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return null;
        }
        if (!authorizationHeader.regionMatches(true, 0, "Basic ", 0, "Basic ".length())) {
            return null;
        }
        String encodedCredentials = authorizationHeader.substring("Basic ".length()).trim();
        if (encodedCredentials.isEmpty()) {
            return null;
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(encodedCredentials);
        } catch (IllegalArgumentException ex) {
            return null;
        }
        String credentials = new String(decoded, StandardCharsets.UTF_8);
        int separatorIndex = credentials.indexOf(':');
        if (separatorIndex <= 0) {
            return null;
        }
        String username = credentials.substring(0, separatorIndex);
        String password = credentials.substring(separatorIndex + 1);
        if (username.isBlank() || password.isBlank()) {
            return null;
        }
        return new BasicCredentials(username, password);
    }

    private static String normalizeBearer(String tokenOrAuthorizationHeader) {
        if (tokenOrAuthorizationHeader == null || tokenOrAuthorizationHeader.isBlank()) {
            return null;
        }
        String trimmed = tokenOrAuthorizationHeader.trim();
        if (trimmed.regionMatches(true, 0, "Bearer ", 0, "Bearer ".length())) {
            String token = trimmed.substring("Bearer ".length()).trim();
            return token.isEmpty() ? null : "Bearer " + token;
        }
        return "Bearer " + trimmed;
    }

    private record BasicCredentials(String username, String password) {
    }
}
