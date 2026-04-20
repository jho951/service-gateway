package com.gateway.audit;

import com.gateway.config.GatewayConfig;
import io.github.jho951.platform.governance.api.AuditEntry;
import io.github.jho951.platform.governance.api.AuditLogRecorder;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;

/** Gateway 요청/오류 감사 이벤트를 platform-governance 감사 API로 기록합니다. */
public final class GatewayAuditService {
    private final boolean enabled;
    private final AuditLogRecorder recorder;

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

    public GatewayAuditService(GatewayConfig config) {
        this.enabled = config.auditLogEnabled();
        if (!enabled) {
            this.recorder = null;
            return;
        }

        this.recorder = new FileAuditLogRecorder(
                Path.of(config.auditLogPath()),
                config.auditLogServiceName(),
                config.auditLogEnv()
        );
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

    private static final class FileAuditLogRecorder implements AuditLogRecorder {
        private final Path filePath;
        private final String serviceName;
        private final String env;

        private FileAuditLogRecorder(Path filePath, String serviceName, String env) {
            this.filePath = filePath;
            this.serviceName = serviceName == null || serviceName.isBlank() ? "unknown-service" : serviceName;
            this.env = env == null || env.isBlank() ? "local" : env;
            ensureParent();
        }

        @Override
        public synchronized void record(AuditEntry entry) {
            try {
                Files.writeString(
                        filePath,
                        toJsonLine(entry),
                        StandardOpenOption.CREATE,
                        StandardOpenOption.WRITE,
                        StandardOpenOption.APPEND
                );
            } catch (IOException ignored) {
                // Audit logging must not block gateway traffic.
            }
        }

        private void ensureParent() {
            try {
                Path parent = filePath.getParent();
                if (parent != null) {
                    Files.createDirectories(parent);
                }
            } catch (IOException ignored) {
                // fail-open
            }
        }

        private String toJsonLine(AuditEntry entry) {
            StringBuilder builder = new StringBuilder();
            builder.append('{')
                    .append("\"service\":\"").append(escape(serviceName)).append("\",")
                    .append("\"env\":\"").append(escape(env)).append("\",")
                    .append("\"category\":\"").append(escape(entry.category())).append("\",")
                    .append("\"message\":\"").append(escape(entry.message())).append("\",")
                    .append("\"occurredAt\":\"").append(escape(entry.occurredAt().toString())).append("\",")
                    .append("\"attributes\":{");

            boolean first = true;
            for (Map.Entry<String, String> attribute : entry.attributes().entrySet()) {
                if (!first) {
                    builder.append(',');
                }
                first = false;
                builder.append("\"").append(escape(attribute.getKey())).append("\":")
                        .append("\"").append(escape(attribute.getValue())).append("\"");
            }

            return builder.append("}}\n").toString();
        }

        private String escape(String value) {
            if (value == null) {
                return "";
            }
            return value
                    .replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r");
        }
    }
}
