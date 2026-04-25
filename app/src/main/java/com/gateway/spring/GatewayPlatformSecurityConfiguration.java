package com.gateway.spring;

import com.gateway.audit.GatewayAuditRecorder;
import com.gateway.audit.GatewayAuditService;
import com.gateway.audit.GatewayFileAuditLogRecorder;
import com.gateway.audit.GatewayOperationalAuditPort;
import com.gateway.auth.AuthServiceClient;
import com.gateway.auth.AuthzServiceClient;
import com.gateway.cache.LocalSessionCache;
import com.gateway.cache.RedisAuthzCache;
import com.gateway.cache.RedisSessionCache;
import com.gateway.cache.RedisSsoSessionStore;
import com.gateway.config.GatewayConfig;
import com.gateway.contract.external.path.AuthApiPaths;
import com.gateway.policy.RequestWindowRateLimiter;
import com.gateway.security.AuthSessionValidator;
import com.gateway.security.AuthTokenVerifier;
import com.gateway.security.InternalJwtIssuer;
import com.gateway.security.JwtPrecheckPolicy;
import io.github.jho951.platform.governance.api.AuditEntry;
import io.github.jho951.platform.governance.api.GovernanceAuditSink;
import io.github.jho951.platform.security.api.PlatformSecurityHybridWebAdapterMarker;
import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityEvaluationService;
import io.github.jho951.platform.security.api.SecurityPolicy;
import io.github.jho951.platform.security.api.SecurityPolicyService;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.api.SecurityVerdict;
import io.github.jho951.platform.security.hybrid.HybridSecurityRuntime;
import io.github.jho951.platform.security.policy.AuthMode;
import io.github.jho951.platform.security.policy.AuthenticationModeResolver;
import io.github.jho951.platform.security.policy.BoundaryIpPolicyProvider;
import io.github.jho951.platform.security.policy.BoundaryRateLimitPolicyProvider;
import io.github.jho951.platform.security.policy.ClientType;
import io.github.jho951.platform.security.policy.ClientTypeResolver;
import io.github.jho951.platform.security.policy.PlatformPrincipalFactory;
import io.github.jho951.platform.security.policy.SecurityAttributes;
import io.github.jho951.platform.security.policy.SecurityBoundary;
import io.github.jho951.platform.security.policy.SecurityBoundaryResolver;
import io.github.jho951.platform.security.policy.SecurityBoundaryType;
import io.github.jho951.platform.security.web.ReactiveSecurityFailureResponseWriter;
import io.github.jho951.platform.security.web.SecurityFailureResponse;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayPlatformSecurityConfiguration {
    public static final String ATTR_BOUNDARY = "gateway.security.boundary";
    public static final String ATTR_CLIENT_TYPE = "gateway.security.clientType";
    public static final String ATTR_AUTH_MODE = "gateway.security.authMode";
    public static final String ATTR_REQUEST_ID = "gateway.security.requestId";
    public static final String ATTR_CORRELATION_ID = "gateway.security.correlationId";
    public static final String ATTR_ORIGINAL_METHOD = "gateway.security.originalMethod";
    public static final String ATTR_ORIGINAL_PATH = "gateway.security.originalPath";
    public static final String ATTR_USER_STATUS = "gateway.security.userStatus";

    @Bean
    public PlatformSecurityHybridWebAdapterMarker gatewayPlatformSecurityHybridWebAdapterMarker() {
        return new PlatformSecurityHybridWebAdapterMarker() {
        };
    }

    @Bean
    public SecurityBoundaryResolver gatewaySecurityBoundaryResolver() {
        return request -> new SecurityBoundary(resolveBoundaryType(request), List.of(request.path()));
    }

    @Bean
    public ClientTypeResolver gatewayClientTypeResolver() {
        return new ClientTypeResolver() {
            @Override
            public ClientType resolve(SecurityRequest request) {
                return resolve(request, null, null);
            }

            @Override
            public ClientType resolve(SecurityRequest request, SecurityContext context, SecurityBoundary boundary) {
                String raw = normalize(request.attributes().get(ATTR_CLIENT_TYPE));
                if (raw != null) {
                    try {
                        return ClientType.valueOf(raw);
                    } catch (IllegalArgumentException ignored) {
                        // fall through
                    }
                }
                if (boundary != null) {
                    return switch (boundary.type()) {
                        case INTERNAL -> ClientType.INTERNAL_SERVICE;
                        case ADMIN -> ClientType.ADMIN_CONSOLE;
                        case PROTECTED -> ClientType.BROWSER;
                        default -> ClientType.EXTERNAL_API;
                    };
                }
                return ClientType.EXTERNAL_API;
            }
        };
    }

    @Bean
    public AuthenticationModeResolver gatewayAuthenticationModeResolver() {
        return new AuthenticationModeResolver() {
            @Override
            public AuthMode resolve(SecurityRequest request, SecurityContext context) {
                return resolve(request, context, null, null);
            }

            @Override
            public AuthMode resolve(SecurityRequest request, SecurityContext context, SecurityBoundary boundary, ClientType clientType) {
                String raw = normalize(request.attributes().get(ATTR_AUTH_MODE));
                if (raw != null) {
                    try {
                        return AuthMode.valueOf(raw);
                    } catch (IllegalArgumentException ignored) {
                        // fall through
                    }
                }
                if (boundary != null && boundary.type() == SecurityBoundaryType.PUBLIC) {
                    return AuthMode.NONE;
                }
                if (context != null && context.authenticated()) {
                    return AuthMode.HYBRID;
                }
                return AuthMode.NONE;
            }
        };
    }

    @Bean
    public PlatformPrincipalFactory platformPrincipalFactory() {
        return context -> {
            if (context == null || !context.authenticated()) {
                return "";
            }
            String principal = context.principal();
            return principal == null ? "" : principal;
        };
    }

    @Bean
    public AuthSessionValidator gatewayAuthSessionValidator(GatewayConfig config) {
        return new AuthSessionValidator(
                config.authServiceUri(),
                new JwtPrecheckPolicy(
                        config.jwtPrecheckExpEnabled(),
                        config.jwtPrecheckExpClockSkewSeconds(),
                        config.jwtPrecheckMaxTokenLength()
                ),
                new AuthTokenVerifier(
                        config.authJwtVerifyEnabled(),
                        config.authJwtPublicKeyPem(),
                        config.authJwtSharedSecret(),
                        config.authJwtKeyId(),
                        config.authJwtAlgorithm(),
                        config.authJwtIssuer(),
                        config.authJwtAudience(),
                        config.authJwtClockSkewSeconds()
                ),
                new AuthServiceClient(config.requestTimeout(), config.authServiceInternalRequestSecret()),
                new LocalSessionCache(config.sessionCacheEnabled() ? config.sessionLocalCacheTtlSeconds() : 0),
                new RedisSessionCache(
                        config.sessionCacheEnabled(),
                        config.redisHost(),
                        config.redisPort(),
                        config.redisPassword(),
                        config.redisTimeoutMs(),
                        config.sessionCacheTtlSeconds(),
                        config.sessionCacheKeyPrefix()
                ),
                new RedisSsoSessionStore(
                        config.redisHost(),
                        config.redisPort(),
                        config.redisPassword(),
                        config.redisTimeoutMs()
                )
        );
    }

    @Bean
    public InternalJwtIssuer gatewayAuthzInternalJwtIssuer(GatewayConfig config) {
        return new InternalJwtIssuer(
                config.authzInternalJwtSharedSecret(),
                config.authzInternalJwtIssuer(),
                config.authzInternalJwtAudience(),
                config.authzInternalJwtTtlSeconds()
        );
    }

    @Bean
    public AuthzServiceClient gatewayAuthzServiceClient(
            GatewayConfig config,
            InternalJwtIssuer gatewayAuthzInternalJwtIssuer
    ) {
        return new AuthzServiceClient(config.requestTimeout(), gatewayAuthzInternalJwtIssuer);
    }

    @Bean
    public RedisAuthzCache gatewayAuthzCache(GatewayConfig config) {
        return new RedisAuthzCache(
                config.authzCacheEnabled(),
                config.redisHost(),
                config.redisPort(),
                config.redisPassword(),
                config.redisTimeoutMs(),
                config.authzCacheTtlSeconds(),
                config.authzCacheKeyPrefix()
        );
    }

    @Bean
    public BoundaryIpPolicyProvider gatewayBoundaryIpPolicyProvider(GatewayConfig config) {
        return boundary -> switch (boundary.type()) {
            case ADMIN -> ipPolicy("ip-guard", config.adminIpPolicy(), "admin ip denied");
            case INTERNAL -> ipPolicy("ip-guard", config.internalIpPolicy(), "internal ip denied");
            default -> allowPolicy("gateway-ip", "gateway-managed-ip-policy");
        };
    }

    @Bean
    public BoundaryRateLimitPolicyProvider gatewayBoundaryRateLimitPolicyProvider(GatewayConfig config) {
        RequestWindowRateLimiter loginRateLimiter = new RequestWindowRateLimiter(config.loginRateLimitPerMinute(), 60_000);
        return boundary -> switch (boundary.type()) {
            case PUBLIC -> loginRateLimitPolicy(loginRateLimiter);
            default -> allowPolicy("gateway-rate-limit", "gateway-managed-rate-limit");
        };
    }

    @Bean
    public SecurityPolicy gatewayAdminAuthorizationPolicy(
            GatewayConfig config,
            AuthzServiceClient gatewayAuthzServiceClient,
            RedisAuthzCache gatewayAuthzCache
    ) {
        return new GatewayAdminAuthorizationPolicy(config, gatewayAuthzServiceClient, gatewayAuthzCache);
    }

    @Bean
    public HybridSecurityRuntime gatewayHybridSecurityRuntime(
            SecurityBoundaryResolver securityBoundaryResolver,
            SecurityPolicyService securityPolicyService,
            SecurityEvaluationService securityEvaluationService
    ) {
        return new HybridSecurityRuntime(
                request -> withResolvedBoundary(request, securityBoundaryResolver),
                (request, context) -> securityPolicyService.evaluate(
                        withResolvedBoundary(request, securityBoundaryResolver),
                        context
                ),
                (request, context) -> securityEvaluationService.evaluateResult(
                        withResolvedBoundary(request, securityBoundaryResolver),
                        context
                ),
                (request, context) -> SecurityFailureResponse.from(
                        securityEvaluationService.evaluateResult(
                                withResolvedBoundary(request, securityBoundaryResolver),
                                context
                        ).verdict()
                )
        );
    }

    @Bean
    public GatewaySecurityEvaluator gatewaySecurityEvaluator(HybridSecurityRuntime gatewayHybridSecurityRuntime) {
        return new PlatformGatewaySecurityEvaluator(gatewayHybridSecurityRuntime);
    }

    @Bean("gatewayPlatformExternalAuditRecorder")
    public GatewayAuditRecorder gatewayPlatformExternalAuditRecorder(GatewayConfig config) {
        return new GatewayFileAuditLogRecorder(
                Path.of(config.auditLogPath()),
                config.auditLogServiceName(),
                config.auditLogEnv()
        );
    }

    @Bean
    public GatewayAuditRecorder gatewayAuditRecorder(
            @Qualifier("gatewayPlatformExternalAuditRecorder") GatewayAuditRecorder externalRecorder
    ) {
        return externalRecorder;
    }

    @Bean
    public GovernanceAuditSink gatewayGovernanceAuditSink(
            @Qualifier("gatewayPlatformExternalAuditRecorder") GatewayAuditRecorder externalRecorder
    ) {
        return externalRecorder::record;
    }

    @Bean
    public GatewayOperationalAuditPort gatewayOperationalAuditPort(
            GatewayConfig config,
            GatewayAuditRecorder gatewayAuditRecorder
    ) {
        return new GatewayAuditService(config.auditLogEnabled(), gatewayAuditRecorder);
    }

    @Bean
    public ReactiveSecurityFailureResponseWriter gatewaySecurityFailureResponseWriter(
            GatewayFailureResponseFactory gatewayFailureResponseFactory,
            GatewayResponseContractWriter gatewayResponseContractWriter
    ) {
        return new GatewayPlatformFailureResponseWriter(gatewayFailureResponseFactory, gatewayResponseContractWriter);
    }

    private static SecurityPolicy allowPolicy(String name, String reason) {
        return new SecurityPolicy() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
                return SecurityVerdict.allow(name, reason);
            }
        };
    }

    private static SecurityPolicy ipPolicy(String name, com.gateway.security.IpGuardPolicy policy, String denyReason) {
        return new SecurityPolicy() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
                if (policy.allows(request.clientIp())) {
                    return SecurityVerdict.allow(name, "ip allowed");
                }
                return SecurityVerdict.deny(name, denyReason);
            }
        };
    }

    private static SecurityPolicy loginRateLimitPolicy(RequestWindowRateLimiter loginRateLimiter) {
        return new SecurityPolicy() {
            @Override
            public String name() {
                return "rate-limiter";
            }

            @Override
            public SecurityVerdict evaluate(SecurityRequest request, SecurityContext context) {
                if (!isLoginPath(request.path())) {
                    return SecurityVerdict.allow(name(), "rate limit bypassed");
                }
                if (loginRateLimiter.allow(request.clientIp())) {
                    return SecurityVerdict.allow(name(), "login rate limit allowed");
                }
                return SecurityVerdict.deny(name(), "login rate limit exceeded");
            }
        };
    }

    private static SecurityBoundaryType resolveBoundaryType(SecurityRequest request) {
        String raw = normalize(request.attributes().get(ATTR_BOUNDARY));
        if (raw == null) {
            return SecurityBoundaryType.PUBLIC;
        }
        return switch (raw) {
            case "INTERNAL" -> SecurityBoundaryType.INTERNAL;
            case "ADMIN" -> SecurityBoundaryType.ADMIN;
            case "PROTECTED" -> SecurityBoundaryType.PROTECTED;
            default -> SecurityBoundaryType.PUBLIC;
        };
    }

    private static String normalize(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        return raw.trim().toUpperCase(Locale.ROOT);
    }

    private static boolean isLoginPath(String path) {
        return AuthApiPaths.LOGIN.equals(path)
                || AuthApiPaths.SSO_START.equals(path)
                || AuthApiPaths.SSO_START_LEGACY.equals(path)
                || AuthApiPaths.OAUTH2_AUTHORIZE_GITHUB.equals(path)
                || path.startsWith("/v1/oauth2/authorization/");
    }

    private static SecurityRequest withResolvedBoundary(
            SecurityRequest request,
            SecurityBoundaryResolver securityBoundaryResolver
    ) {
        SecurityBoundary boundary = securityBoundaryResolver.resolve(request);
        Map<String, String> attributes = new LinkedHashMap<>(request.attributes());
        attributes.put(SecurityAttributes.BOUNDARY, boundary.type().name());
        attributes.put(SecurityAttributes.BOUNDARY_PATTERNS, String.join(",", boundary.patterns()));
        return new SecurityRequest(
                request.subject(),
                request.clientIp(),
                request.path(),
                request.action(),
                attributes,
                request.occurredAt()
        );
    }


    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
