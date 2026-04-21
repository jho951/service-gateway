package com.gateway.auth;

import com.gateway.contract.internal.header.TraceHeaders;
import com.gateway.contract.internal.header.ServiceHeaders;

import java.util.Map;
import java.util.List;

/**
 * 인증 서비스(Auth Service)의 검증 결과를 객체화하고,
 * 내부 시스템(Microservices)이 사용할 수 있는 형식으로 변환합니다.
 */
public final class AuthResult {
    private final int statusCode;
    private final boolean authenticated;
    private final String userId;
    private final String role;
    private final String status;
    private final String sessionId;
    private final String email;
    private final String name;
    private final String avatarUrl;

    /**
     * 값이 null일 경우 빈 문자열("")로 치환
     * 헤더 등에 값을 넣을 때 발생할 수 있는 NullPointerException을 방지
     * @param value 인증 결과 데이터(userId, role, status, sessionId)
     * @return value ? value : null
     */
    private static String safe(String value) {
        if(value == null) return "";
        return value;
    }

    /**
     * 생성자
     * @param statusCode 인증 서버의 응답 상태
     * @param authenticated 인증 성공 여부 (true/false)
     * @param userId 사용자 식별자
     * @param role 사용자 권한
     * @param status 상태
     * @param sessionId 세션 정보
     */
    public AuthResult(int statusCode, boolean authenticated, String userId, String role, String status, String sessionId) {
        this(statusCode, authenticated, userId, role, status, sessionId, "", "", "");
    }

    public AuthResult(
            int statusCode,
            boolean authenticated,
            String userId,
            String role,
            String status,
            String sessionId,
            String email,
            String name,
            String avatarUrl
    ) {
        this.statusCode = statusCode;
        this.authenticated = authenticated;
        this.userId = userId;
        this.role = role;
        this.status = status;
        this.sessionId = sessionId;
        this.email = email;
        this.name = name;
        this.avatarUrl = avatarUrl;
    }

    public int getStatusCode() {return statusCode;}
    public boolean isAuthenticated() {return authenticated;}
    public String getUserId() {
        return userId;
    }
    public String getRole() {
        return role;
    }
    public String getStatus() {
        return status;
    }
    public String getSessionId() {return sessionId;}
    public String getEmail() { return email; }
    public String getName() { return name; }
    public String getAvatarUrl() { return avatarUrl; }
    public boolean isAdmin() {return "ADMIN".equalsIgnoreCase(role);}

    /**
     * 내부 보안용 헤더 생성자
     * @param requestId 클라이언트가 서버에 보낸 단일 HTTP 요청에 부여되는 고유 번호
     * @param correlationId 하나의 비즈니스 로직을 처리하기 위해 여러 서비스를 거치는 전체 과정을 관통하는 고유 번호
     * @return Map<String, List<String>>
     */
    public Map<String, List<String>> toTrustedHeaders(String requestId, String correlationId) {
        return Map.of(
                ServiceHeaders.Trusted.USER_ID, List.of(safe(userId)),
                ServiceHeaders.Trusted.USER_ROLE, List.of(safe(role)),
                ServiceHeaders.Trusted.SESSION_ID, List.of(safe(sessionId)),
                TraceHeaders.REQUEST_ID, List.of(requestId),
                TraceHeaders.CORRELATION_ID, List.of(correlationId)
        );
    }
}
