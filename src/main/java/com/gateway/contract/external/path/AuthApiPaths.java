package com.gateway.contract.external.path;

/** 인증 및 로그인 */
public final class AuthApiPaths {
    private AuthApiPaths() {}

    public static final String API_PREFIX = "/v1";
    public static final String LOGIN = "/v1/auth/login";
    public static final String OAUTH2_AUTHORIZE_ALL = "/v1/auth/oauth2/authorize/**";
    public static final String SSO_START = "/v1/auth/sso/start";
    public static final String EXCHANGE = "/v1/auth/exchange";
    public static final String ME = "/v1/auth/me";
    public static final String REFRESH = "/v1/auth/refresh";
    public static final String LOGOUT = "/v1/auth/logout";
    public static final String INTERNAL_ALL = "/v1/auth/internal/**";
    public static final String OAUTH2_AUTHORIZATION_ALL = "/v1/oauth2/**";
    public static final String LOGIN_OAUTH2_CALLBACK_ALL = "/v1/login/oauth2/**";
    public static final String JWKS = "/v1/.well-known/jwks.json";
    public static final String ERROR = "/v1/error";
}
