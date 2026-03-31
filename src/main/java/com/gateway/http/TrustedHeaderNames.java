package com.gateway.http;

import com.gateway.contract.internal.header.ServiceHeaders;
import com.gateway.contract.internal.header.TraceHeaders;

import java.util.Set;

/** 게이트웨이가 재주입하는 trusted header 이름 모음입니다. */
public final class TrustedHeaderNames {
    /** 인스턴스 화 방지 */
    private TrustedHeaderNames() {}

    public static final Set<String> ALL = Set.of(
            ServiceHeaders.Trusted.USER_ID.toLowerCase(),
            ServiceHeaders.Trusted.USER_ROLE.toLowerCase(),
            ServiceHeaders.Trusted.USER_STATUS.toLowerCase(),
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


}
