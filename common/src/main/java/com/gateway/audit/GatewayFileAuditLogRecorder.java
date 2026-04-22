package com.gateway.audit;

import io.github.jho951.platform.governance.api.AuditEntry;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Map;

/** AuditEntry를 JSON lines 파일로 기록하는 governance 호환 recorder입니다. */
public final class GatewayFileAuditLogRecorder implements GatewayAuditRecorder {
    private final Path filePath;
    private final String serviceName;
    private final String env;

    public GatewayFileAuditLogRecorder(Path filePath, String serviceName, String env) {
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
