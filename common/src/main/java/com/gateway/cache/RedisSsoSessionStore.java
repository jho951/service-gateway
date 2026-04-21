package com.gateway.cache;

import com.gateway.auth.AuthResult;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** auth-service가 저장한 SSO session payload를 Redis에서 직접 읽는 fallback store입니다. */
public final class RedisSsoSessionStore {
    private static final Pattern USER_ID_FIELD = Pattern.compile("\"userId\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern EMAIL_FIELD = Pattern.compile("\"email\"\\s*:\\s*\"([^\"]*)\"");
    private static final Pattern NAME_FIELD = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]*)\"");
    private static final Pattern AVATAR_URL_FIELD = Pattern.compile("\"avatarUrl\"\\s*:\\s*\"([^\"]*)\"");
    private static final Pattern STATUS_FIELD = Pattern.compile("\"status\"\\s*:\\s*\"([^\"]*)\"");
    private static final Pattern NESTED_ROLE_FIELD = Pattern.compile(
            "\"roles\"\\s*:\\s*\\[\\s*\"[^\"]+\"\\s*,\\s*\\[\\s*\"([^\"]+)\"",
            Pattern.DOTALL
    );
    private static final Pattern FLAT_ROLE_FIELD = Pattern.compile(
            "\"roles\"\\s*:\\s*\\[\\s*\"([^\"]+)\"",
            Pattern.DOTALL
    );
    private static final String SESSION_PREFIX = "auth:session:";

    private final String host;
    private final int port;
    private final String password;
    private final int timeoutMs;

    public RedisSsoSessionStore(String host, int port, String password, int timeoutMs) {
        this.host = host;
        this.port = port;
        this.password = password;
        this.timeoutMs = timeoutMs;
    }

    public AuthResult get(String sessionId) throws IOException {
        if (sessionId == null || sessionId.isBlank()) {
            return null;
        }
        try (RedisConnection connection = new RedisConnection(host, port, timeoutMs, password)) {
            String raw = connection.get(SESSION_PREFIX + sessionId);
            return parse(sessionId, raw);
        }
    }

    static AuthResult parse(String sessionId, String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String userId = firstField(raw, USER_ID_FIELD);
        if (userId == null || userId.isBlank()) {
            return null;
        }
        return new AuthResult(
                200,
                true,
                userId,
                extractRole(raw),
                firstField(raw, STATUS_FIELD),
                sessionId,
                firstField(raw, EMAIL_FIELD),
                firstField(raw, NAME_FIELD),
                firstField(raw, AVATAR_URL_FIELD)
        );
    }

    private static String firstField(String payload, Pattern pattern) {
        Matcher matcher = pattern.matcher(payload);
        if (!matcher.find()) {
            return "";
        }
        return matcher.group(1);
    }

    private static String extractRole(String payload) {
        String nestedRole = firstField(payload, NESTED_ROLE_FIELD);
        if (!nestedRole.isBlank()) {
            return nestedRole;
        }
        return firstField(payload, FLAT_ROLE_FIELD);
    }
}
