package com.gateway.config;

import com.gateway.contract.external.path.AuthApiPaths;
import com.gateway.contract.external.path.DocumentApiPaths;
import com.gateway.contract.external.path.InternalApiPaths;
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
    private final URI blockServiceUri;
    private final URI permissionServiceUri;
    private final URI adminPermissionVerifyUri;
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
    private final boolean advancedRoutePoliciesEnabled;
    private final boolean adminPermissionCheckEnabled;
    private final boolean permissionCacheEnabled;
    private final String redisHost;
    private final int redisPort;
    private final String redisPassword;
    private final int redisTimeoutMs;
    private final int permissionCacheTtlSeconds;
    private final String permissionCacheKeyPrefix;
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
    private final boolean oauthDebugLogEnabled;
    private final boolean auditLogEnabled;
    private final String auditLogPath;
    private final String auditLogServiceName;
    private final String auditLogEnv;
    private final boolean auditLogAsyncEnabled;
    private final int auditLogAsyncThreads;
    private final String internalJwtSharedSecret;
    private final String internalJwtIssuer;
    private final String internalJwtAudience;
    private final int internalJwtTtlSeconds;
    private final String internalRequestSecret;

    /**
     * 생성자
     * @param bindAddress 게이트웨이가 바인딩할 호스트와 포트
     * @param requestTimeout 외부 요청과 업스트림 호출에 공통 적용할 타임아웃
     * @param authServiceUri auth-service 기본 URI
     * @param userServiceUri user-service 기본 URI
     * @param blockServiceUri block-service 기본 URI
     * @param permissionServiceUri permission-service 기본 URI
     * @param adminPermissionVerifyUri 관리자 권한 검증용 내부 호출 URI
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
     * @param advancedRoutePoliciesEnabled 세분화된 라우트/인증 정책 활성화 여부
     * @param adminPermissionCheckEnabled 관리자 권한 추가 검증 활성화 여부
     * @param permissionCacheEnabled 관리자 권한 검증 결과 캐시 활성화 여부
     * @param redisHost Redis 호스트
     * @param redisPort Redis 포트
     * @param redisPassword Redis 비밀번호
     * @param redisTimeoutMs Redis 연결/응답 타임아웃(ms)
     * @param permissionCacheTtlSeconds 관리자 권한 캐시 TTL(초)
     * @param permissionCacheKeyPrefix 관리자 권한 캐시 키 prefix
     * @param sessionCacheEnabled 세션 캐시 활성화 여부
     * @param sessionLocalCacheTtlSeconds 로컬 메모리 세션 캐시 TTL(초)
     * @param sessionCacheTtlSeconds 분산 세션 캐시 TTL(초)
     * @param sessionCacheKeyPrefix 세션 캐시 키 prefix
     * @param oauthDebugLogEnabled OAuth 관련 디버그 로그 활성화 여부
     * @param auditLogEnabled 감사 로그 활성화 여부
     * @param auditLogPath 감사 로그 파일 경로
     * @param auditLogServiceName 감사 로그에 기록할 서비스 이름
     * @param auditLogEnv 감사 로그에 기록할 실행 환경 이름
     * @param auditLogAsyncEnabled 감사 로그 비동기 기록 활성화 여부
     * @param auditLogAsyncThreads 감사 로그 비동기 처리 스레드 수
     * @param internalJwtSharedSecret Gateway 내부 JWT 서명용 shared secret
     * @param internalJwtIssuer Gateway 내부 JWT issuer
     * @param internalJwtAudience Gateway 내부 JWT audience
     * @param internalJwtTtlSeconds Gateway 내부 JWT 만료 시간(초)
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
            URI blockServiceUri,
            URI permissionServiceUri,
            URI adminPermissionVerifyUri,
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
            boolean advancedRoutePoliciesEnabled,
            boolean adminPermissionCheckEnabled,
            boolean permissionCacheEnabled,
            String redisHost,
            int redisPort,
            String redisPassword,
            int redisTimeoutMs,
            int permissionCacheTtlSeconds,
            String permissionCacheKeyPrefix,
            boolean sessionCacheEnabled,
            int sessionLocalCacheTtlSeconds,
            int sessionCacheTtlSeconds,
            String sessionCacheKeyPrefix,
            boolean oauthDebugLogEnabled,
            boolean auditLogEnabled,
            String auditLogPath,
            String auditLogServiceName,
            String auditLogEnv,
            boolean auditLogAsyncEnabled,
            int auditLogAsyncThreads,
            String internalJwtSharedSecret,
            String internalJwtIssuer,
            String internalJwtAudience,
            int internalJwtTtlSeconds,
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
        this.blockServiceUri = blockServiceUri;
        this.permissionServiceUri = permissionServiceUri;
        this.adminPermissionVerifyUri = adminPermissionVerifyUri;
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
        this.advancedRoutePoliciesEnabled = advancedRoutePoliciesEnabled;
        this.adminPermissionCheckEnabled = adminPermissionCheckEnabled;
        this.permissionCacheEnabled = permissionCacheEnabled;
        this.redisHost = redisHost;
        this.redisPort = redisPort;
        this.redisPassword = redisPassword;
        this.redisTimeoutMs = redisTimeoutMs;
        this.permissionCacheTtlSeconds = permissionCacheTtlSeconds;
        this.permissionCacheKeyPrefix = permissionCacheKeyPrefix;
        this.sessionCacheEnabled = sessionCacheEnabled;
        this.sessionLocalCacheTtlSeconds = sessionLocalCacheTtlSeconds;
        this.sessionCacheTtlSeconds = sessionCacheTtlSeconds;
        this.sessionCacheKeyPrefix = sessionCacheKeyPrefix;
        this.oauthDebugLogEnabled = oauthDebugLogEnabled;
        this.auditLogEnabled = auditLogEnabled;
        this.auditLogPath = auditLogPath;
        this.auditLogServiceName = auditLogServiceName;
        this.auditLogEnv = auditLogEnv;
        this.auditLogAsyncEnabled = auditLogAsyncEnabled;
        this.auditLogAsyncThreads = auditLogAsyncThreads;
        this.internalJwtSharedSecret = internalJwtSharedSecret;
        this.internalJwtIssuer = internalJwtIssuer;
        this.internalJwtAudience = internalJwtAudience;
        this.internalJwtTtlSeconds = internalJwtTtlSeconds;
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
        boolean advancedRoutePoliciesEnabled = false;
        boolean adminPermissionCheckEnabled = false;
        boolean permissionCacheEnabled = false;
        String redisHost = env.getOrDefault("REDIS_HOST", "127.0.0.1");
        int redisPort = parseInt(env.get("REDIS_PORT"), 6379, "REDIS_PORT");
        String redisPassword = env.get("REDIS_PASSWORD");
        int redisTimeoutMs = parseInt(env.get("REDIS_TIMEOUT_MS"), 1000, "REDIS_TIMEOUT_MS");
        int permissionCacheTtlSeconds = parseInt(env.get("GATEWAY_PERMISSION_CACHE_TTL_SECONDS"), 300, "GATEWAY_PERMISSION_CACHE_TTL_SECONDS");
        String permissionCacheKeyPrefix = env.getOrDefault("GATEWAY_PERMISSION_CACHE_PREFIX", "gateway:admin-permission:");
        boolean sessionCacheEnabled = parseBoolean(env.get("GATEWAY_SESSION_CACHE_ENABLED"), true);
        int sessionLocalCacheTtlSeconds = parseInt(env.get("GATEWAY_SESSION_LOCAL_CACHE_TTL_SECONDS"), 3, "GATEWAY_SESSION_LOCAL_CACHE_TTL_SECONDS");
        int sessionCacheTtlSeconds = parseInt(env.get("GATEWAY_SESSION_CACHE_TTL_SECONDS"), 60, "GATEWAY_SESSION_CACHE_TTL_SECONDS");
        String sessionCacheKeyPrefix = env.getOrDefault("GATEWAY_SESSION_CACHE_KEY_PREFIX", "gateway:session:");
        boolean oauthDebugLogEnabled = parseBoolean(env.get("GATEWAY_OAUTH_DEBUG_LOG_ENABLED"), false);
        boolean auditLogEnabled = parseBoolean(env.get("GATEWAY_AUDIT_LOG_ENABLED"), true);
        String auditLogPath = env.getOrDefault("GATEWAY_AUDIT_LOG_PATH", "./logs/audit.log");
        String auditLogServiceName = env.getOrDefault("GATEWAY_AUDIT_SERVICE_NAME", "api-gateway-server");
        String auditLogEnv = env.getOrDefault("APP_ENV", "local");
        boolean auditLogAsyncEnabled = parseBoolean(env.get("GATEWAY_AUDIT_LOG_ASYNC_ENABLED"), true);
        int auditLogAsyncThreads = parseInt(env.get("GATEWAY_AUDIT_LOG_ASYNC_THREADS"), 2, "GATEWAY_AUDIT_LOG_ASYNC_THREADS");

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
        String internalRequestSecret = nullIfBlank(env.get("GATEWAY_INTERNAL_REQUEST_SECRET"));
        if (internalRequestSecret == null) internalRequestSecret = internalJwtSharedSecret;

        URI authServiceUri = requiredUri(env.get("AUTH_SERVICE_URL"), "AUTH_SERVICE_URL");
        URI userServiceUri = requiredUri(env.get("USER_SERVICE_URL"), "USER_SERVICE_URL");
        URI blockServiceUri = requiredUri(env.get("BLOCK_SERVICE_URL"), "BLOCK_SERVICE_URL");
        URI permissionServiceUri = optionalUri(env.get("PERMISSION_SERVICE_URL"));

        URI adminPermissionVerifyUri = null;

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

        List<RouteDefinition> routes = buildRoutes(authServiceUri, userServiceUri, blockServiceUri, permissionServiceUri);

        return new GatewayConfig(
                new InetSocketAddress(host, port),
                Duration.ofMillis(requestTimeoutMs),
                authServiceUri,
                userServiceUri,
                blockServiceUri,
                permissionServiceUri,
                adminPermissionVerifyUri,
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
                advancedRoutePoliciesEnabled,
                adminPermissionCheckEnabled,
                permissionCacheEnabled,
                redisHost,
                redisPort,
                redisPassword,
                redisTimeoutMs,
                permissionCacheTtlSeconds,
                permissionCacheKeyPrefix,
                sessionCacheEnabled,
                sessionLocalCacheTtlSeconds,
                sessionCacheTtlSeconds,
                sessionCacheKeyPrefix,
                oauthDebugLogEnabled,
                auditLogEnabled,
                auditLogPath,
                auditLogServiceName,
                auditLogEnv,
                auditLogAsyncEnabled,
                auditLogAsyncThreads,
                internalJwtSharedSecret,
                internalJwtIssuer,
                internalJwtAudience,
                internalJwtTtlSeconds,
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
            URI blockServiceUri,
            URI permissionServiceUri
    ) {
        List<RouteDefinition> routes = new ArrayList<>();
        routes.add(new RouteDefinition(AuthApiPaths.INTERNAL_ALL, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.LOGIN, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.OAUTH2_AUTHORIZE_ALL, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.SSO_START, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.SSO_START_LEGACY, RouteType.PUBLIC, "auth", authServiceUri));
        routes.add(new RouteDefinition(AuthApiPaths.EXCHANGE, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.REFRESH, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.LOGOUT, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.OAUTH2_AUTHORIZATION_ALL, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.LOGIN_OAUTH2_CALLBACK_ALL, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.JWKS, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.ME, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(AuthApiPaths.ERROR, RouteType.PUBLIC, "auth", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(InternalApiPaths.INTERNAL_ALL, RouteType.INTERNAL, "internal", authServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(UserApiPaths.SIGNUP, RouteType.PUBLIC, "user", userServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(UserApiPaths.ME, RouteType.PROTECTED, "user", userServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(UserApiPaths.INTERNAL_FIND_OR_CREATE_AND_LINK_SOCIAL, RouteType.INTERNAL, "user", userServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(UserApiPaths.INTERNAL_USERS_ALL, RouteType.INTERNAL, "user", userServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(DocumentApiPaths.DOCUMENTS_ALL, RouteType.PROTECTED, "block", blockServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(DocumentApiPaths.WORKSPACES_ALL, RouteType.PROTECTED, "block", blockServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(DocumentApiPaths.EDITOR_OPERATIONS_ALL, RouteType.PROTECTED, "block", blockServiceUri, AuthApiPaths.API_PREFIX));
        routes.add(new RouteDefinition(DocumentApiPaths.ADMIN_ALL, RouteType.PROTECTED, "block", blockServiceUri, AuthApiPaths.API_PREFIX));
//        if (permissionServiceUri != null) {
//            routes.add(new RouteDefinition(PermissionApiPaths.ALL, RouteType.PROTECTED, "permission", permissionServiceUri));
//        }
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

    public InetSocketAddress bindAddress() {
        return bindAddress;
    }
    public Duration requestTimeout() {
        return requestTimeout;
    }
    public URI authServiceUri() {
        return authServiceUri;
    }
    public URI userServiceUri() {
        return userServiceUri;
    }
    public URI blockServiceUri() {
        return blockServiceUri;
    }
    public URI permissionServiceUri() {
        return permissionServiceUri;
    }
    public URI adminPermissionVerifyUri() {
        return adminPermissionVerifyUri;
    }
    public List<String> allowedOrigins() {
        return allowedOrigins;
    }
    public IpGuardPolicy ipPolicy() {
        return ipPolicy;
    }
    public IpGuardPolicy internalIpPolicy() {
        return internalIpPolicy;
    }
    public IpGuardPolicy adminIpPolicy() {
        return adminIpPolicy;
    }
    public int loginRateLimitPerMinute() {
        return loginRateLimitPerMinute;
    }
    public int maxBodyBytes() {
        return maxBodyBytes;
    }
    public boolean jwtPrecheckExpEnabled() {
        return jwtPrecheckExpEnabled;
    }
    public int jwtPrecheckExpClockSkewSeconds() {
        return jwtPrecheckExpClockSkewSeconds;
    }
    public int jwtPrecheckMaxTokenLength() {
        return jwtPrecheckMaxTokenLength;
    }
    public List<String> gatewayUserIdClaimNames() {
        return gatewayUserIdClaimNames;
    }
    public boolean forwardAuthorizationHeader() {
        return forwardAuthorizationHeader;
    }
    public boolean permissionCacheEnabled() {return permissionCacheEnabled;}
    public boolean adminPermissionCheckEnabled() {return adminPermissionCheckEnabled;}
    public boolean advancedRoutePoliciesEnabled() {return advancedRoutePoliciesEnabled;}
    public String redisHost() {return redisHost;}
    public int redisPort() {return redisPort;}
    public String redisPassword() {return redisPassword;}
    public int redisTimeoutMs() {return redisTimeoutMs;}
    public int permissionCacheTtlSeconds() {return permissionCacheTtlSeconds;}
    public String permissionCacheKeyPrefix() {return permissionCacheKeyPrefix;}
    public boolean sessionCacheEnabled() {return sessionCacheEnabled;}
    public int sessionLocalCacheTtlSeconds() {return sessionLocalCacheTtlSeconds;}
    public int sessionCacheTtlSeconds() {return sessionCacheTtlSeconds;}
    public String sessionCacheKeyPrefix() {return sessionCacheKeyPrefix;}
    public boolean oauthDebugLogEnabled() {return oauthDebugLogEnabled;}
    public boolean auditLogEnabled() {return auditLogEnabled;}
    public String auditLogPath() {return auditLogPath;}
    public String auditLogServiceName() {return auditLogServiceName;}
    public String auditLogEnv() {return auditLogEnv;}
    public boolean auditLogAsyncEnabled() {return auditLogAsyncEnabled;}
    public int auditLogAsyncThreads() {return auditLogAsyncThreads;}
    public String internalJwtSharedSecret() {return internalJwtSharedSecret;}
    public String internalJwtIssuer() {return internalJwtIssuer;}
    public String internalJwtAudience() {return internalJwtAudience;}
    public int internalJwtTtlSeconds() {return internalJwtTtlSeconds;}
    public String internalRequestSecret() {return internalRequestSecret;}
    public boolean authJwtVerifyEnabled() {return authJwtVerifyEnabled;}
    public String authJwtPublicKeyPem() {return authJwtPublicKeyPem;}
    public String authJwtSharedSecret() {return authJwtSharedSecret;}
    public String authJwtKeyId() {return authJwtKeyId;}
    public String authJwtAlgorithm() {return authJwtAlgorithm;}
    public String authJwtIssuer() {return authJwtIssuer;}
    public String authJwtAudience() {return authJwtAudience;}
    public long authJwtClockSkewSeconds() {return authJwtClockSkewSeconds;}
    public List<RouteDefinition> routes() {return routes;}
}
