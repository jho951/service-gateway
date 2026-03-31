package com.gateway.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

/** 내부 서비스 전달용 HS256 JWT 발급기입니다. */
public final class InternalJwtIssuer {
    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

    private final byte[] secretBytes;
    private final String issuer;
    private final String audience;
    private final long ttlSeconds;

    public InternalJwtIssuer(String sharedSecret, String issuer, String audience, long ttlSeconds) {
        if (sharedSecret == null) throw new IllegalArgumentException("GATEWAY_INTERNAL_JWT_SHARED_SECRET must be configured");
        if (sharedSecret.isBlank()) throw new IllegalArgumentException("GATEWAY_INTERNAL_JWT_SHARED_SECRET must be configured");
        this.secretBytes = sharedSecret.getBytes(StandardCharsets.UTF_8);
        this.issuer = issuer == null || issuer.isBlank() ? "api-gateway" : issuer;
        this.audience = audience == null || audience.isBlank() ? "internal-services" : audience;
        this.ttlSeconds = Math.max(30L, ttlSeconds);
    }

    public String issueForUser(String userId, String status) {
        if (userId == null) throw new IllegalArgumentException("userId must not be blank");
        if (userId.isBlank()) throw new IllegalArgumentException("userId must not be blank");
        long now = Instant.now().getEpochSecond();
        long exp = now + ttlSeconds;
        String normalizedStatus = status == null || status.isBlank() ? "A" : status;

        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payloadJson = "{\"sub\":\"" + escapeJson(userId) + "\","
                + "\"userId\":\"" + escapeJson(userId) + "\","
                + "\"status\":\"" + escapeJson(normalizedStatus) + "\","
                + "\"iss\":\"" + escapeJson(issuer) + "\","
                + "\"aud\":\"" + escapeJson(audience) + "\","
                + "\"iat\":" + now + ","
                + "\"exp\":" + exp + "}";

        String encodedHeader = encode(headerJson);
        String encodedPayload = encode(payloadJson);
        String signingInput = encodedHeader + "." + encodedPayload;
        String signature = sign(signingInput);
        return "Bearer " + signingInput + "." + signature;
    }

    private String sign(String signingInput) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secretBytes, "HmacSHA256"));
            byte[] signature = mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII));
            return BASE64_URL.encodeToString(signature);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to sign internal JWT", ex);
        }
    }

    private static String encode(String json) {
        return BASE64_URL.encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
