package com.gateway.audit;

import io.github.jho951.platform.governance.api.AuditEntry;

public interface GatewayAuditRecorder {
    void record(AuditEntry entry);
}
