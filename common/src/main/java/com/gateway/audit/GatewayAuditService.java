package com.gateway.audit;

import io.github.jho951.platform.governance.api.AuditEntry;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/** Gateway 요청/오류 감사 이벤트를 platform-governance 감사 API로 기록합니다. */
public final class GatewayAuditService implements GatewayOperationalAuditPort {
    private final boolean enabled;
    private final GatewayAuditRecorder recorder;

    private static String resolveEventType(String method) {
        if (method == null) {
            return "CUSTOM";
        }
        return switch (method.toUpperCase()) {
            case "GET", "HEAD" -> "READ";
            case "POST" -> "CREATE";
            case "PUT", "PATCH" -> "UPDATE";
            case "DELETE" -> "DELETE";
            default -> "CUSTOM";
        };
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    public GatewayAuditService(boolean enabled, GatewayAuditRecorder recorder) {
        this.enabled = enabled;
        this.recorder = enabled ? recorder : null;
    }

    @Override
    public void logRequest(
            String method,
            String path,
            String requestId,
            String clientIp,
            String userId,
            String upstream,
            int statusCode,
            String authOutcome,
            String failureReason
    ) {
        if (!enabled || recorder == null) return;

        String actorId = (userId == null || userId.isBlank()) ? "anonymous" : userId;
        String actorType = (userId == null || userId.isBlank()) ? "ANONYMOUS" : "USER";

        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("eventType", resolveEventType(method));
        attributes.put("actorId", actorId);
        attributes.put("actorType", actorType);
        attributes.put("resourceType", "HTTP_PATH");
        attributes.put("resourceId", safe(path));
        attributes.put("result", statusCode < 400 ? "SUCCESS" : "FAILURE");
        attributes.put("reason", safe(failureReason));
        attributes.put("traceId", safe(requestId));
        attributes.put("requestId", safe(requestId));
        attributes.put("clientIp", safe(clientIp));
        attributes.put("method", safe(method));
        attributes.put("upstream", safe(upstream));
        attributes.put("status", String.valueOf(statusCode));
        attributes.put("authOutcome", safe(authOutcome));

        recorder.record(new AuditEntry("gateway", "GATEWAY_PROXY_REQUEST", attributes, Instant.now()));
    }
}
