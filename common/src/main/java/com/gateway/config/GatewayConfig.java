package com.gateway.config;

import com.gateway.contract.external.path.AuthApiPaths;
import com.gateway.contract.external.path.DocumentApiPaths;
import com.gateway.contract.external.path.UserApiPaths;
import com.gateway.routing.RouteDefinition;
import com.gateway.routing.RouteType;
import com.gateway.security.IpGuardPolicy;

import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** API Gateway 라우트 설정 */
public final class GatewayConfig {
    private final InetSocketAddress bindAddress;
    private final Duration requestTimeout;
    private final URI authServiceUri;
    private final URI userServiceUri;
    private final URI editorServiceUri;
    private final URI authzAdminVerifyUri;
    private final List<String> allowedOrigins;
    private final IpGuardPolicy ipPolicy;
    private final IpGuardPolicy internalIpPolicy;
    private final IpGuardPolicy adminIpPolicy;
    private final int loginRateLimitPerMinute;
    private final int maxBodyBytes;
    private final boolean jwtPrecheckExpEnabled;
    private final int jwtPrecheckExpClockSkewSeconds;
    private final int jwtPrecheckMaxTokenLength;
    private final List<String> gatewayUserIdClaimNames;
    private final boolean forwardAuthorizationHeader;
    private final boolean authzAdminCheckEnabled;
    private final boolean authzCacheEnabled;
    private final String redisHost;
    private final int redisPort;
    private final String redisPassword;
    private final int redisTimeoutMs;
    private final int authzCacheTtlSeconds;
    private final String authzCacheKeyPrefix;
    private final List<RouteDefinition> routes;

    private final boolean authJwtVerifyEnabled;
    private final String authJwtPublicKeyPem;
    private final String authJwtSharedSecret;
    private final String authJwtKeyId;
    private final String authJwtAlgorithm;
    private final String authJwtIssuer;
    private final String authJwtAudience;
    private final long authJwtClockSkewSeconds;
    private final boolean sessionCacheEnabled;
    private final int sessionLocalCacheTtlSeconds;
    private final int sessionCacheTtlSeconds;
    private final String sessionCacheKeyPrefix;
    private final boolean auditLogEnabled;
    private final String auditLogPath;
    private final String auditLogServiceName;
    private final String auditLogEnv;
    private final String internalJwtSharedSecret;
    private final String internalJwtIssuer;
    private final String internalJwtAudience;
    private final int internalJwtTtlSeconds;
    private final String authzInternalJwtSharedSecret;
    private final String authzInternalJwtIssuer;
    private final String authzInternalJwtAudience;
    private final int authzInternalJwtTtlSeconds;
    private final String authServiceInternalRequestSecret;
    private final String internalRequestSecret;

    /**
     * 생성자
     * @param bindAddress 게이트웨이가 바인딩할 호스트와 포트
     * @param requestTimeout 외부 요청과 업스트림 호출에 공통 적용할 타임아웃
     * @param authServiceUri auth-service 기본 URI
     * @param userServiceUri user-service 기본 URI
     * @param editorServiceUri editor-service 기본 URI
     * @param authzAdminVerifyUri 관리자 권한 검증용 내부 호출 URI
     * @param allowedOrigins CORS 허용 Origin 목록
     * @param ipPolicy 일반 외부 IP 허용 정책
     * @param internalIpPolicy 내부 서비스 호출 IP 허용 정책
     * @param adminIpPolicy 관리자 경로에 적용할 IP 허용 정책
     * @param loginRateLimitPerMinute 로그인 요청 rate limit
     * @param maxBodyBytes 허용하는 최대 요청 본문 크기(bytes)
     * @param jwtPrecheckExpEnabled JWT exp 사전 점검 활성화 여부
     * @param jwtPrecheckExpClockSkewSeconds JWT exp 사전 점검 허용 오차(초)
     * @param jwtPrecheckMaxTokenLength JWT 사전 점검 시 허용할 최대 토큰 길이
     * @param gatewayUserIdClaimNames userId 추출에 사용할 JWT claim 이름 목록
     * @param forwardAuthorizationHeader upstream으로 Authorization 헤더를 전달할지 여부
     * @param authzAdminCheckEnabled 관리자 권한 추가 검증 활성화 여부
     * @param authzCacheEnabled 관리자 권한 검증 결과 캐시 활성화 여부
     * @param redisHost Redis 호스트
     * @param redisPort Redis 포트
     * @param redisPassword Redis 비밀번호
     * @param redisTimeoutMs Redis 연결/응답 타임아웃(ms)
     * @param authzCacheTtlSeconds 관리자 권한 캐시 TTL(초)
     * @param authzCacheKeyPrefix 관리자 권한 캐시 키 prefix
     * @param sessionCacheEnabled 세션 캐시 활성화 여부
     * @param sessionLocalCacheTtlSeconds 로컬 메모리 세션 캐시 TTL(초)
     * @param sessionCacheTtlSeconds 분산 세션 캐시 TTL(초)
     * @param sessionCacheKeyPrefix 세션 캐시 키 prefix
     * @param auditLogEnabled 감사 로그 활성화 여부
     * @param auditLogPath 감사 로그 파일 경로
     * @param auditLogServiceName 감사 로그에 기록할 서비스 이름
     * @param auditLogEnv 감사 로그에 기록할 실행 환경 이름
     * @param internalJwtSharedSecret Gateway 내부 JWT 서명용 shared secret
     * @param internalJwtIssuer Gateway 내부 JWT issuer
     * @param internalJwtAudience Gateway 내부 JWT audience
     * @param internalJwtTtlSeconds Gateway 내부 JWT 만료 시간(초)
     * @param authzInternalJwtSharedSecret authz-service 내부 호출 JWT 서명용 shared secret
     * @param authzInternalJwtIssuer authz-service 내부 호출 JWT issuer
     * @param authzInternalJwtAudience authz-service 내부 호출 JWT audience
     * @param authzInternalJwtTtlSeconds authz-service 내부 호출 JWT 만료 시간(초)
     * @param authServiceInternalRequestSecret auth-service 내부 세션 검증 호출용 caller proof secret
     * @param internalRequestSecret INTERNAL 라우트 접근 시 요구되는 호출 주체 비밀값
     * @param routes Gateway 라우팅 정의 목록
     * @param authJwtVerifyEnabled auth-service 토큰 서명 검증 활성화 여부
     * @param authJwtPublicKeyPem RSA 계열 JWT 검증용 공개키 PEM
     * @param authJwtSharedSecret HS 계열 JWT 검증용 shared secret
     * @param authJwtKeyId JWT 헤더 kid 필터링용 키 ID
     * @param authJwtAlgorithm 기대하는 JWT 서명 알고리즘
     * @param authJwtIssuer 기대하는 JWT issuer
     * @param authJwtAudience 기대하는 JWT audience
     * @param authJwtClockSkewSeconds JWT exp 검증 시 허용할 clock skew(초)
     */
    private GatewayConfig(
            InetSocketAddress bindAddress,
            Duration requestTimeout,
            URI authServiceUri,
            URI userServiceUri,
            URI editorServiceUri,
            URI authzAdminVerifyUri,
            List<String> allowedOrigins,
            IpGuardPolicy ipPolicy,
            IpGuardPolicy internalIpPolicy,
            IpGuardPolicy adminIpPolicy,
            int loginRateLimitPerMinute,
            int maxBodyBytes,
            boolean jwtPrecheckExpEnabled,
            int jwtPrecheckExpClockSkewSeconds,
            int jwtPrecheckMaxTokenLength,
            List<String> gatewayUserIdClaimNames,
            boolean forwardAuthorizationHeader,
            boolean authzAdminCheckEnabled,
            boolean authzCacheEnabled,
            String redisHost,
            int redisPort,
            String redisPassword,
            int redisTimeoutMs,
            int authzCacheTtlSeconds,
            String authzCacheKeyPrefix,
            boolean sessionCacheEnabled,
            int sessionLocalCacheTtlSeconds,
            int sessionCacheTtlSeconds,
            String sessionCacheKeyPrefix,
            boolean auditLogEnabled,
            String auditLogPath,
            String auditLogServiceName,
            String auditLogEnv,
            String internalJwtSharedSecret,
            String internalJwtIssuer,
            String internalJwtAudience,
            int internalJwtTtlSeconds,
            String authzInternalJwtSharedSecret,
            String authzInternalJwtIssuer,
            String authzInternalJwtAudience,
            int authzInternalJwtTtlSeconds,
            String authServiceInternalRequestSecret,
            String internalRequestSecret,
            List<RouteDefinition> routes,
            boolean authJwtVerifyEnabled,
            String authJwtPublicKeyPem,
            String authJwtSharedSecret,
            String authJwtKeyId,
            String authJwtAlgorithm,
            String authJwtIssuer,
            String authJwtAudience,
            long authJwtClockSkewSeconds
    ) {
        this.bindAddress = bindAddress;
        this.requestTimeout = requestTimeout;
        this.authServiceUri = authServiceUri;
        this.userServiceUri = userServiceUri;
        this.editorServiceUri = editorServiceUri;
        this.authzAdminVerifyUri = authzAdminVerifyUri;
        this.allowedOrigins = allowedOrigins;
        this.ipPolicy = ipPolicy;
        this.internalIpPolicy = internalIpPolicy;
        this.adminIpPolicy = adminIpPolicy;
        this.loginRateLimitPerMinute = loginRateLimitPerMinute;
        this.maxBodyBytes = maxBodyBytes;
        this.jwtPrecheckExpEnabled = jwtPrecheckExpEnabled;
        this.jwtPrecheckExpClockSkewSeconds = jwtPrecheckExpClockSkewSeconds;
        this.jwtPrecheckMaxTokenLength = jwtPrecheckMaxTokenLength;
        this.gatewayUserIdClaimNames = gatewayUserIdClaimNames;
        this.forwardAuthorizationHeader = forwardAuthorizationHeader;
        this.authzAdminCheckEnabled = authzAdminCheckEnabled;
        this.authzCacheEnabled = authzCacheEnabled;
        this.redisHost = redisHost;
        this.redisPort = redisPort;
        this.redisPassword = redisPassword;
        this.redisTimeoutMs = redisTimeoutMs;
        this.authzCacheTtlSeconds = authzCacheTtlSeconds;
        this.authzCacheKeyPrefix = authzCacheKeyPrefix;
        this.sessionCacheEnabled = sessionCacheEnabled;
        this.sessionLocalCacheTtlSeconds = sessionLocalCacheTtlSeconds;
        this.sessionCacheTtlSeconds = sessionCacheTtlSeconds;
        this.sessionCacheKeyPrefix = sessionCacheKeyPrefix;
        this.auditLogEnabled = auditLogEnabled;
        this.auditLogPath = auditLogPath;
        this.auditLogServiceName = auditLogServiceName;
        this.auditLogEnv = auditLogEnv;
        this.internalJwtSharedSecret = internalJwtSharedSecret;
        this.internalJwtIssuer = internalJwtIssuer;
        this.internalJwtAudience = internalJwtAudience;
        this.internalJwtTtlSeconds = internalJwtTtlSeconds;
        this.authzInternalJwtSharedSecret = authzInternalJwtSharedSecret;
        this.authzInternalJwtIssuer = authzInternalJwtIssuer;
        this.authzInternalJwtAudience = authzInternalJwtAudience;
        this.authzInternalJwtTtlSeconds = authzInternalJwtTtlSeconds;
        this.authServiceInternalRequestSecret = authServiceInternalRequestSecret;
        this.internalRequestSecret = internalRequestSecret;
        this.routes = routes;
        this.authJwtVerifyEnabled = authJwtVerifyEnabled;
        this.authJwtPublicKeyPem = authJwtPublicKeyPem;
        this.authJwtSharedSecret = authJwtSharedSecret;
        this.authJwtKeyId = authJwtKeyId;
        this.authJwtAlgorithm = authJwtAlgorithm;
        this.authJwtIssuer = authJwtIssuer;
        this.authJwtAudience = authJwtAudience;
        this.authJwtClockSkewSeconds = authJwtClockSkewSeconds;
    }

    /**
     * GatewayConfig 생성자에 넣는 팩토리 메서드
     * @param env 시스템 환경 변수 맵
     * @return 검증이 끝난 불변 설정 객체
     */
    public static GatewayConfig fromEnv(Map<String, String> env) {
        String host = env.getOrDefault("GATEWAY_BIND", "0.0.0.0");
        int port = parseInt(env.get("GATEWAY_PORT"), 8080, "GATEWAY_PORT");
        int requestTimeoutMs = parseInt(env.get("GATEWAY_REQUEST_TIMEOUT_MS"), 30_000, "GATEWAY_REQUEST_TIMEOUT_MS");
        int loginRateLimitPerMinute = parseInt(env.get("GATEWAY_LOGIN_RATE_LIMIT_PER_MINUTE"), 20, "GATEWAY_LOGIN_RATE_LIMIT_PER_MINUTE");
        int maxBodyBytes = parseInt(env.get("GATEWAY_MAX_BODY_BYTES"), 1_048_576, "GATEWAY_MAX_BODY_BYTES");
        boolean jwtPrecheckExpEnabled = parseBoolean(env.get("GATEWAY_JWT_PRECHECK_EXP_ENABLED"), false);
        int jwtPrecheckExpClockSkewSeconds = parseInt(env.get("GATEWAY_JWT_PRECHECK_EXP_CLOCK_SKEW_SECONDS"), 30, "GATEWAY_JWT_PRECHECK_EXP_CLOCK_SKEW_SECONDS");
        int jwtPrecheckMaxTokenLength = parseInt(env.get("GATEWAY_JWT_PRECHECK_MAX_TOKEN_LENGTH"), 4096, "GATEWAY_JWT_PRECHECK_MAX_TOKEN_LENGTH");
        List<String> gatewayUserIdClaimNames = EnvParsers.csvOrDefault(env.get("GATEWAY_USER_ID_CLAIMS"), List.of("sub", "userId"));
        boolean forwardAuthorizationHeader = parseBoolean(env.get("GATEWAY_FORWARD_AUTHORIZATION_HEADER"), false);
        boolean authzCacheEnabled = parseBoolean(env.get("GATEWAY_AUTHZ_CACHE_ENABLED"), false);
        String redisHost = env.getOrDefault("REDIS_HOST", "127.0.0.1");
        int redisPort = parseInt(env.get("REDIS_PORT"), 6379, "REDIS_PORT");
        String redisPassword = env.get("REDIS_PASSWORD");
        int redisTimeoutMs = parseInt(env.get("REDIS_TIMEOUT_MS"), 1000, "REDIS_TIMEOUT_MS");
        int authzCacheTtlSeconds = parseInt(env.get("GATEWAY_AUTHZ_CACHE_TTL_SECONDS"), 300, "GATEWAY_AUTHZ_CACHE_TTL_SECONDS");
        String authzCacheKeyPrefix = env.getOrDefault("GATEWAY_AUTHZ_CACHE_PREFIX", "gateway:admin-authz:");
        boolean sessionCacheEnabled = parseBoolean(env.get("GATEWAY_SESSION_CACHE_ENABLED"), true);
        int sessionLocalCacheTtlSeconds = parseInt(env.get("GATEWAY_SESSION_LOCAL_CACHE_TTL_SECONDS"), 3, "GATEWAY_SESSION_LOCAL_CACHE_TTL_SECONDS");
        int sessionCacheTtlSeconds = parseInt(env.get("GATEWAY_SESSION_CACHE_TTL_SECONDS"), 60, "GATEWAY_SESSION_CACHE_TTL_SECONDS");
        String sessionCacheKeyPrefix = env.getOrDefault("GATEWAY_SESSION_CACHE_KEY_PREFIX", "gateway:session:");
        boolean auditLogEnabled = parseBoolean(env.get("GATEWAY_AUDIT_LOG_ENABLED"), true);
        String auditLogPath = env.getOrDefault("GATEWAY_AUDIT_LOG_PATH", "./logs/audit.log");
        String auditLogServiceName = env.getOrDefault("GATEWAY_AUDIT_SERVICE_NAME", "gateway-service");
        String auditLogEnv = env.getOrDefault("APP_ENV", "local");

        boolean rawAuthJwtVerifyEnabled = parseBoolean(env.get("AUTH_JWT_VERIFY_ENABLED"), false);
        String authJwtPublicKeyPem = nullIfBlank(env.get("AUTH_JWT_PUBLIC_KEY_PEM"));
        String authJwtSharedSecret = nullIfBlank(env.get("AUTH_JWT_SHARED_SECRET"));
        boolean authJwtVerifyEnabled = rawAuthJwtVerifyEnabled && (authJwtPublicKeyPem != null || authJwtSharedSecret != null);
        if (rawAuthJwtVerifyEnabled && authJwtPublicKeyPem == null && authJwtSharedSecret == null) {
            throw new IllegalArgumentException("AUTH_JWT_PUBLIC_KEY_PEM or AUTH_JWT_SHARED_SECRET must be configured when AUTH_JWT_VERIFY_ENABLED is true");
        }
        String authJwtKeyId = env.get("AUTH_JWT_KEY_ID");
        String authJwtAlgorithm = env.getOrDefault("AUTH_JWT_ALGORITHM", "RS256");
        String authJwtIssuer = env.get("AUTH_JWT_ISSUER");
        String authJwtAudience = env.get("AUTH_JWT_AUDIENCE");
        int authJwtClockSkewSeconds = parseInt(env.get("AUTH_JWT_CLOCK_SKEW_SECONDS"), 30, "AUTH_JWT_CLOCK_SKEW_SECONDS");

        String internalJwtSharedSecret = nullIfBlank(env.get("GATEWAY_INTERNAL_JWT_SHARED_SECRET"));
        if (internalJwtSharedSecret == null) internalJwtSharedSecret = authJwtSharedSecret;
        if (internalJwtSharedSecret == null) internalJwtSharedSecret = "dev-internal-jwt-secret";
        String internalJwtIssuer = env.getOrDefault("GATEWAY_INTERNAL_JWT_ISSUER", "api-gateway");
        String internalJwtAudience = env.getOrDefault("GATEWAY_INTERNAL_JWT_AUDIENCE", "internal-services");
        int internalJwtTtlSeconds = parseInt(env.get("GATEWAY_INTERNAL_JWT_TTL_SECONDS"), 300, "GATEWAY_INTERNAL_JWT_TTL_SECONDS");
        String authzInternalJwtSharedSecret = nullIfBlank(env.get("AUTHZ_INTERNAL_JWT_SECRET"));
        if (authzInternalJwtSharedSecret == null) authzInternalJwtSharedSecret = internalJwtSharedSecret;
        String authzInternalJwtIssuer = env.getOrDefault("AUTHZ_INTERNAL_JWT_ISSUER", internalJwtIssuer);
        String authzInternalJwtAudience = env.getOrDefault("AUTHZ_INTERNAL_JWT_AUDIENCE", "authz-service");
        int authzInternalJwtTtlSeconds = parseInt(
                env.get("AUTHZ_INTERNAL_JWT_TTL_SECONDS"),
                internalJwtTtlSeconds,
                "AUTHZ_INTERNAL_JWT_TTL_SECONDS"
        );
        String internalRequestSecret = nullIfBlank(env.get("GATEWAY_INTERNAL_REQUEST_SECRET"));
        if (internalRequestSecret == null) internalRequestSecret = internalJwtSharedSecret;
        String authServiceInternalRequestSecret = nullIfBlank(env.get("AUTH_SERVICE_INTERNAL_REQUEST_SECRET"));
        if (authServiceInternalRequestSecret == null) authServiceInternalRequestSecret = nullIfBlank(env.get("AUTH_INTERNAL_REQUEST_SECRET"));
        if (authServiceInternalRequestSecret == null) authServiceInternalRequestSecret = internalRequestSecret;

        URI authServiceUri = requiredUri(env.get("AUTH_SERVICE_URL"), "AUTH_SERVICE_URL");
        URI userServiceUri = requiredUri(env.get("USER_SERVICE_URL"), "USER_SERVICE_URL");
        String editorServiceUrl = env.get("EDITOR_SERVICE_URL");
        if (editorServiceUrl == null || editorServiceUrl.isBlank()) editorServiceUrl = env.get("BLOCK_SERVICE_URL");
        URI editorServiceUri = requiredUri(editorServiceUrl, "EDITOR_SERVICE_URL");
        URI authzAdminVerifyUri = optionalUri(env.get("AUTHZ_ADMIN_VERIFY_URL"));
        boolean authzAdminCheckEnabled = authzAdminVerifyUri != null;

        List<String> allowedOrigins = EnvParsers.csvOrDefault(env.get("GATEWAY_CORS_ALLOWED_ORIGINS"), List.of("*"));

        IpGuardPolicy ipPolicy = new IpGuardPolicy(
                parseBoolean(env.get("GATEWAY_IP_GUARD_ENABLED"), true),
                EnvParsers.csvOrDefault(env.get("GATEWAY_ALLOWED_IPS"), List.of("*")),
                parseBoolean(env.get("GATEWAY_IP_GUARD_DEFAULT_ALLOW"), false)
        );
        IpGuardPolicy internalIpPolicy = new IpGuardPolicy(
                parseBoolean(env.get("GATEWAY_INTERNAL_IP_GUARD_ENABLED"), true),
                EnvParsers.csvOrDefault(env.get("GATEWAY_INTERNAL_ALLOWED_IPS"), List.of("127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")),
                parseBoolean(env.get("GATEWAY_INTERNAL_IP_GUARD_DEFAULT_ALLOW"), false)
        );
        IpGuardPolicy adminIpPolicy = new IpGuardPolicy(
                parseBoolean(env.get("GATEWAY_ADMIN_IP_GUARD_ENABLED"), true),
                EnvParsers.csvOrDefault(env.get("GATEWAY_ADMIN_ALLOWED_IPS"), List.of("127.0.0.1")),
                parseBoolean(env.get("GATEWAY_ADMIN_IP_GUARD_DEFAULT_ALLOW"), false)
        );

        List<RouteDefinition> routes = buildRoutes(authServiceUri, userServiceUri, editorServiceUri);

        return new GatewayConfig(
                new InetSocketAddress(host, port),
                Duration.ofMillis(requestTimeoutMs),
                authServiceUri,
                userServiceUri,
                editorServiceUri,
                authzAdminVerifyUri,
                allowedOrigins,
                ipPolicy,
                internalIpPolicy,
                adminIpPolicy,
                loginRateLimitPerMinute,
                maxBodyBytes,
                jwtPrecheckExpEnabled,
                jwtPrecheckExpClockSkewSeconds,
                jwtPrecheckMaxTokenLength,
                gatewayUserIdClaimNames,
                forwardAuthorizationHeader,
                authzAdminCheckEnabled,
                authzCacheEnabled,
                redisHost,
                redisPort,
                redisPassword,
                redisTimeoutMs,
                authzCacheTtlSeconds,
                authzCacheKeyPrefix,
                sessionCacheEnabled,
                sessionLocalCacheTtlSeconds,
                sessionCacheTtlSeconds,
                sessionCacheKeyPrefix,
                auditLogEnabled,
                auditLogPath,
                auditLogServiceName,
                auditLogEnv,
                internalJwtSharedSecret,
                internalJwtIssuer,
                internalJwtAudience,
                internalJwtTtlSeconds,
                authzInternalJwtSharedSecret,
                authzInternalJwtIssuer,
                authzInternalJwtAudience,
                authzInternalJwtTtlSeconds,
                authServiceInternalRequestSecret,
                internalRequestSecret,
                routes,
                authJwtVerifyEnabled,
                authJwtPublicKeyPem,
                authJwtSharedSecret,
                authJwtKeyId,
                authJwtAlgorithm,
                authJwtIssuer,
                authJwtAudience,
                authJwtClockSkewSeconds
        );
    }

    private static List<RouteDefinition> buildRoutes(
            URI authServiceUri,
            URI userServiceUri,
            URI editorServiceUri
    ) {
        List<RouteDefinition> routes = new ArrayList<>();
        routes.add(new RouteDefinition(AuthApiPaths.LOGIN, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.LOGIN_GITHUB, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.OAUTH2_AUTHORIZE_GITHUB, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.SSO_START, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.SSO_START_LEGACY, RouteType.PUBLIC, "auth", authServiceUri));
        routes.add(new RouteDefinition(AuthApiPaths.EXCHANGE, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.REFRESH, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.LOGOUT, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.SESSION, RouteType.PROTECTED, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.OAUTH2_AUTHORIZATION_ALL, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.LOGIN_OAUTH2_CALLBACK_ALL, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.JWKS, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.ME, RouteType.PROTECTED, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.ERROR, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(UserApiPaths.SIGNUP, RouteType.PUBLIC, "user", userServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(UserApiPaths.ME, RouteType.PROTECTED, "user", userServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(DocumentApiPaths.DOCUMENTS_ALL, RouteType.PROTECTED, "editor", editorServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(DocumentApiPaths.BLOCKS_ALL, RouteType.PROTECTED, "editor", editorServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(DocumentApiPaths.EDITOR_OPERATIONS_ALL, RouteType.PROTECTED, "editor", editorServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(DocumentApiPaths.ADMIN_ALL, RouteType.ADMIN, "editor", editorServiceUri, AuthApiPaths.API_PREFIX));
        routes.sort(RouteDefinition.MOST_SPECIFIC_FIRST);
        return List.copyOf(routes);
    }

    private static URI optionalUri(String rawValue) {
        if (rawValue == null) return null;
        if ( rawValue.isBlank()) return null;
        URI uri = URI.create(rawValue.trim());
        if (uri.getScheme() == null) throw new IllegalArgumentException("Service URL Scheme must be absolute: " + rawValue);
        if(uri.getHost() == null) throw new IllegalArgumentException("Service URL Host must be absolute: " + rawValue);
        return uri;
    }

    private static URI requiredUri(String rawValue, String key) {
        URI uri = optionalUri(rawValue);
        if (uri == null) throw new IllegalArgumentException(key + " must be configured");
        return uri;
    }

    private static int parseInt(String rawValue, int defaultValue, String key) {
        if (rawValue == null) return defaultValue;
        if (rawValue.isBlank()) return defaultValue;

        try {
            return Integer.parseInt(rawValue.trim());
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException(key + " must be a valid integer", ex);
        }
    }

    private static boolean parseBoolean(String rawValue, boolean defaultValue) {
        if (rawValue == null) return defaultValue;
        if (rawValue.isBlank()) return defaultValue;
        return Boolean.parseBoolean(rawValue.trim());
    }

    private static String nullIfBlank(String rawValue) {
        if (rawValue == null) return null;
        if (rawValue.isBlank()) return null;
        return rawValue;
    }

    /** 게이트웨이가 바인딩할 네트워크 주소를 반환합니다. */
    public InetSocketAddress bindAddress() {
        return bindAddress;
    }
    /** 외부 요청과 업스트림 호출에 공통으로 사용하는 타임아웃을 반환합니다. */
    public Duration requestTimeout() {
        return requestTimeout;
    }
    /** auth-service 기본 URI를 반환합니다. */
    public URI authServiceUri() {
        return authServiceUri;
    }
    /** user-service 기본 URI를 반환합니다. */
    public URI userServiceUri() {
        return userServiceUri;
    }
    /** editor-service 기본 URI를 반환합니다. */
    public URI editorServiceUri() {
        return editorServiceUri;
    }
    /** 관리자 권한 검증용 내부 호출 URI를 반환합니다. */
    public URI authzAdminVerifyUri() {
        return authzAdminVerifyUri;
    }
    /** CORS 허용 Origin 목록을 반환합니다. */
    public List<String> allowedOrigins() {
        return allowedOrigins;
    }
    /** 외부 요청에 적용할 IP 허용 정책을 반환합니다. */
    public IpGuardPolicy ipPolicy() {
        return ipPolicy;
    }
    /** 내부 서비스 호출에 적용할 IP 허용 정책을 반환합니다. */
    public IpGuardPolicy internalIpPolicy() {
        return internalIpPolicy;
    }
    /** 관리자 경로에 적용할 IP 허용 정책을 반환합니다. */
    public IpGuardPolicy adminIpPolicy() {
        return adminIpPolicy;
    }
    /** 로그인 요청 rate limit 값을 반환합니다. */
    public int loginRateLimitPerMinute() {
        return loginRateLimitPerMinute;
    }
    /** 허용하는 최대 요청 본문 크기(bytes)를 반환합니다. */
    public int maxBodyBytes() {
        return maxBodyBytes;
    }
    /** JWT exp 사전 점검 활성화 여부를 반환합니다. */
    public boolean jwtPrecheckExpEnabled() {
        return jwtPrecheckExpEnabled;
    }
    /** JWT exp 사전 점검 허용 오차(초)를 반환합니다. */
    public int jwtPrecheckExpClockSkewSeconds() {
        return jwtPrecheckExpClockSkewSeconds;
    }
    /** JWT 사전 점검 시 허용할 최대 토큰 길이를 반환합니다. */
    public int jwtPrecheckMaxTokenLength() {
        return jwtPrecheckMaxTokenLength;
    }
    /** userId 추출에 사용할 JWT claim 이름 목록을 반환합니다. */
    public List<String> gatewayUserIdClaimNames() {
        return gatewayUserIdClaimNames;
    }
    /** upstream으로 Authorization 헤더를 전달할지 여부를 반환합니다. */
    public boolean forwardAuthorizationHeader() {
        return forwardAuthorizationHeader;
    }
    /** 관리자 권한 검증 캐시 활성화 여부를 반환합니다. */
    public boolean authzCacheEnabled() {return authzCacheEnabled;}
    /** 관리자 권한 추가 검증 활성화 여부를 반환합니다. */
    public boolean authzAdminCheckEnabled() {return authzAdminCheckEnabled;}
    /** Redis 호스트를 반환합니다. */
    public String redisHost() {return redisHost;}
    /** Redis 포트를 반환합니다. */
    public int redisPort() {return redisPort;}
    /** Redis 비밀번호를 반환합니다. */
    public String redisPassword() {return redisPassword;}
    /** Redis 연결/응답 타임아웃(ms)을 반환합니다. */
    public int redisTimeoutMs() {return redisTimeoutMs;}
    /** 관리자 권한 캐시 TTL(초)을 반환합니다. */
    public int authzCacheTtlSeconds() {return authzCacheTtlSeconds;}
    /** 관리자 권한 캐시 키 prefix를 반환합니다. */
    public String authzCacheKeyPrefix() {return authzCacheKeyPrefix;}
    /** 세션 캐시 활성화 여부를 반환합니다. */
    public boolean sessionCacheEnabled() {return sessionCacheEnabled;}
    /** 로컬 메모리 세션 캐시 TTL(초)을 반환합니다. */
    public int sessionLocalCacheTtlSeconds() {return sessionLocalCacheTtlSeconds;}
    /** 분산 세션 캐시 TTL(초)을 반환합니다. */
    public int sessionCacheTtlSeconds() {return sessionCacheTtlSeconds;}
    /** 세션 캐시 키 prefix를 반환합니다. */
    public String sessionCacheKeyPrefix() {return sessionCacheKeyPrefix;}
    /** 감사 로그 활성화 여부를 반환합니다. */
    public boolean auditLogEnabled() {return auditLogEnabled;}
    /** 감사 로그 파일 경로를 반환합니다. */
    public String auditLogPath() {return auditLogPath;}
    /** 감사 로그에 기록할 서비스 이름을 반환합니다. */
    public String auditLogServiceName() {return auditLogServiceName;}
    /** 감사 로그에 기록할 실행 환경 이름을 반환합니다. */
    public String auditLogEnv() {return auditLogEnv;}
    /** Gateway 내부 JWT 서명용 shared secret을 반환합니다. */
    public String internalJwtSharedSecret() {return internalJwtSharedSecret;}
    /** Gateway 내부 JWT issuer를 반환합니다. */
    public String internalJwtIssuer() {return internalJwtIssuer;}
    /** Gateway 내부 JWT audience를 반환합니다. */
    public String internalJwtAudience() {return internalJwtAudience;}
    /** Gateway 내부 JWT 만료 시간(초)을 반환합니다. */
    public int internalJwtTtlSeconds() {return internalJwtTtlSeconds;}
    /** authz-service 내부 호출 JWT 서명용 shared secret을 반환합니다. */
    public String authzInternalJwtSharedSecret() {return authzInternalJwtSharedSecret;}
    /** authz-service 내부 호출 JWT issuer를 반환합니다. */
    public String authzInternalJwtIssuer() {return authzInternalJwtIssuer;}
    /** authz-service 내부 호출 JWT audience를 반환합니다. */
    public String authzInternalJwtAudience() {return authzInternalJwtAudience;}
    /** authz-service 내부 호출 JWT 만료 시간(초)을 반환합니다. */
    public int authzInternalJwtTtlSeconds() {return authzInternalJwtTtlSeconds;}
    /** auth-service 내부 세션 검증 호출에 보낼 caller proof secret을 반환합니다. */
    public String authServiceInternalRequestSecret() {return authServiceInternalRequestSecret;}
    /** INTERNAL 라우트 접근 시 요구되는 호출 주체 비밀값을 반환합니다. */
    public String internalRequestSecret() {return internalRequestSecret;}
    /** auth-service 토큰 검증 활성화 여부를 반환합니다. */
    public boolean authJwtVerifyEnabled() {return authJwtVerifyEnabled;}
    /** RSA 계열 JWT 검증용 공개키 PEM을 반환합니다. */
    public String authJwtPublicKeyPem() {return authJwtPublicKeyPem;}
    /** HS 계열 JWT 검증용 shared secret을 반환합니다. */
    public String authJwtSharedSecret() {return authJwtSharedSecret;}
    /** JWT 헤더 kid 필터링용 키 ID를 반환합니다. */
    public String authJwtKeyId() {return authJwtKeyId;}
    /** 기대하는 JWT 서명 알고리즘을 반환합니다. */
    public String authJwtAlgorithm() {return authJwtAlgorithm;}
    /** 기대하는 JWT issuer를 반환합니다. */
    public String authJwtIssuer() {return authJwtIssuer;}
    /** 기대하는 JWT audience를 반환합니다. */
    public String authJwtAudience() {return authJwtAudience;}
    /** JWT exp 검증 시 허용할 clock skew(초)를 반환합니다. */
    public long authJwtClockSkewSeconds() {return authJwtClockSkewSeconds;}
    /** Gateway 라우팅 정의 목록을 반환합니다. */
    public List<RouteDefinition> routes() {return routes;}
}
