package com.gateway.api;

/** Gateway에서 사용하는 모든 접속 경로를 한곳에 모아둔 상수 클래스입니다. */
public final class GatewayApiPaths {
    /** 인스턴스화 방지 */
    private GatewayApiPaths() {}

    /** 서버 상태 체크 */
    public static final String HEALTH = "/health";
    public static final String READY = "/ready";

    /** 인증 및 로그인 */
    public static final String AUTH_LOGIN_GITHUB = "/auth/login/github";
    public static final String AUTH_OAUTH_GITHUB_CALLBACK = "/auth/oauth/github/callback";
    public static final String AUTH_SESSION = "/auth/session";
    public static final String AUTH_INTERNAL_ALL = "/auth/internal/**";

    /** 사용자 및 데이터 서비스 */
    public static final String USERS_ME = "/users/me";
    public static final String BLOCKS_ALL = "/blocks/**";
    public static final String PERMISSIONS_ALL = "/permissions/**";

    /** 관리자 전용 */
    public static final String ADMIN_USERS_ALL = "/admin/users/**";
    public static final String ADMIN_BLOCKS_ALL = "/admin/blocks/**";
    public static final String ADMIN_PERMISSIONS_ALL = "/admin/permissions/**";

    /** 서버들끼리만 주고받는 내부 전용 */
    public static final String INTERNAL_ALL = "/internal/**";
}
