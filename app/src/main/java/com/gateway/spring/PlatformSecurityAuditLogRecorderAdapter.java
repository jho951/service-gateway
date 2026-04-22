package com.gateway.spring;

import com.gateway.audit.GatewayAuditRecorder;
import io.github.jho951.platform.governance.api.AuditEntry;
import io.github.jho951.platform.governance.api.AuditLogRecorder;

public final class PlatformSecurityAuditLogRecorderAdapter implements AuditLogRecorder {
    private final GatewayAuditRecorder delegate;

    public PlatformSecurityAuditLogRecorderAdapter(GatewayAuditRecorder delegate) {
        this.delegate = delegate;
    }

    @Override
    public void record(AuditEntry entry) {
        delegate.record(entry);
    }
}
