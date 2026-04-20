package com.gateway.http;

import com.gateway.contract.internal.header.ServiceHeaders;
import com.gateway.contract.internal.header.TraceHeaders;

import java.util.Set;

/** 게이트웨이가 재주입하는 trusted header 이름 모음입니다. */
public final class TrustedHeaderNames {
    /** 인스턴스 화 방지 */
    private TrustedHeaderNames() {}

    private static final Set<String> EXACT = Set.of(
            ServiceHeaders.Trusted.SESSION_ID.toLowerCase(),
            ServiceHeaders.Trusted.CLIENT_TYPE.toLowerCase(),
            ServiceHeaders.Auth.INTERNAL_REQUEST_SECRET.toLowerCase(),
            TraceHeaders.REQUEST_ID.toLowerCase(),
            TraceHeaders.CORRELATION_ID.toLowerCase(),
            "x-auth-user-id",
            "x-auth-session-id",
            "x-auth-roles",
            "x-auth-subject",
            "x-auth-authenticated"
    );

    public static boolean isTrusted(String headerName) {
        if (headerName == null || headerName.isBlank()) {
            return false;
        }
        String normalized = headerName.toLowerCase();
        return EXACT.contains(normalized) || normalized.startsWith("x-user-");
    }
}
