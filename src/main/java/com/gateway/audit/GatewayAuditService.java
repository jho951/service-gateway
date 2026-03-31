package com.gateway.audit;

import com.auditlog.api.AuditSink;
import com.auditlog.api.AuditEvent;
import com.auditlog.api.AuditLogger;
import com.auditlog.api.AuditResult;
import com.auditlog.api.AuditEventType;
import com.auditlog.api.AuditActorType;
import com.auditlog.core.FileAuditSink;
import com.auditlog.core.DefaultAuditLogger;

import com.gateway.config.GatewayConfig;

import java.util.List;
import java.nio.file.Path;

/** Gateway 요청/오류 감사 이벤트를 audit-log 모듈로 기록합니다. */
public final class GatewayAuditService {
    private final boolean enabled;
    private final AuditLogger logger;

    private static AuditEventType resolveEventType(String method) {
        if (method == null) {
            return AuditEventType.CUSTOM;
        }
        return switch (method.toUpperCase()) {
            case "GET", "HEAD" -> AuditEventType.READ;
            case "POST" -> AuditEventType.CREATE;
            case "PUT", "PATCH" -> AuditEventType.UPDATE;
            case "DELETE" -> AuditEventType.DELETE;
            default -> AuditEventType.CUSTOM;
        };
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    public GatewayAuditService(GatewayConfig config) {
        this.enabled = config.auditLogEnabled();
        if (!enabled) {
            this.logger = null;
            return;
        }

        AuditSink sink = new FileAuditSink(
                Path.of(config.auditLogPath()),
                config.auditLogServiceName(),
                config.auditLogEnv()
        );
        this.logger = new DefaultAuditLogger(sink, List.of(), null);
    }

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
        if (!enabled || logger == null) return;

        String actorId = (userId == null || userId.isBlank()) ? "anonymous" : userId;
        AuditResult result = statusCode < 400 ? AuditResult.SUCCESS : AuditResult.FAILURE;
        AuditActorType actorType = (userId == null || userId.isBlank()) ? AuditActorType.ANONYMOUS : AuditActorType.USER;

        AuditEvent event = AuditEvent.builder(resolveEventType(method), "GATEWAY_PROXY_REQUEST")
                .actor(actorId, actorType, null)
                .resource("HTTP_PATH", path)
                .result(result)
                .reason(failureReason)
                .traceId(requestId)
                .requestId(requestId)
                .clientIp(clientIp)
                .detail("requestId", safe(requestId))
                .detail("method", safe(method))
                .detail("upstream", safe(upstream))
                .detail("status", String.valueOf(statusCode))
                .detail("authOutcome", safe(authOutcome))
                .build();

        logger.log(event);
    }
}
