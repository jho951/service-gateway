package com.gateway.security;

import com.gateway.auth.AuthResult;
import com.gateway.auth.AuthServiceClient;
import com.gateway.cache.LocalSessionCache;
import com.gateway.cache.RedisSsoSessionStore;
import com.gateway.cache.RedisSessionCache;

import java.io.IOException;
import java.net.URI;
import java.util.logging.Level;
import java.util.logging.Logger;

/** JWT + 세션 검증을 위한 L1/L2 캐시를 관리하고 Auth Service로 fall back 하는 클래스입니다. */
public final class AuthSessionValidator {
    private static final Logger log = Logger.getLogger(AuthSessionValidator.class.getName());

    private final URI authServiceUri;
    private final JwtPrecheckPolicy jwtPrecheckPolicy;
    private final AuthTokenVerifier tokenVerifier;
    private final AuthServiceClient authServiceClient;
    private final LocalSessionCache localCache;
    private final RedisSessionCache redisCache;
    private final RedisSsoSessionStore redisSsoSessionStore;

    /**
     * 생성자
     * @param authServiceUri
     * @param jwtPrecheckPolicy
     * @param tokenVerifier
     * @param authServiceClient
     * @param localCache
     * @param redisCache
     */
    public AuthSessionValidator(
            URI authServiceUri,
            JwtPrecheckPolicy jwtPrecheckPolicy,
            AuthTokenVerifier tokenVerifier,
            AuthServiceClient authServiceClient,
            LocalSessionCache localCache,
            RedisSessionCache redisCache,
            RedisSsoSessionStore redisSsoSessionStore
    ) {
        this.authServiceUri = authServiceUri;
        this.jwtPrecheckPolicy = jwtPrecheckPolicy;
        this.tokenVerifier = tokenVerifier;
        this.authServiceClient = authServiceClient;
        this.localCache = localCache;
        this.redisCache = redisCache;
        this.redisSsoSessionStore = redisSsoSessionStore;
    }

    public AuthVerificationResult verifyBearer(String authorizationHeader, String requestId, String correlationId) throws IOException, InterruptedException {
        JwtPrecheckPolicy.Result precheckResult = jwtPrecheckPolicy == null
                ? JwtPrecheckPolicy.Result.accepted("PRECHECK_BYPASSED")
                : jwtPrecheckPolicy.precheck(authorizationHeader);
        if (!precheckResult.accepted()) {
            return AuthVerificationResult.failed(AuthTokenVerifier.Result.rejected(precheckResult.outcome()));
        }

        String token = extractToken(authorizationHeader);
        if (token.isEmpty()) return AuthVerificationResult.failed(AuthTokenVerifier.Result.rejected("INVALID_AUTH_HEADER"));
        String cacheKey = SessionCacheKey.fromToken(token);

        CachedAuth cached = loadCachedAuthResult(cacheKey);
        if (cached != null) return AuthVerificationResult.fromCache(cached.authResult(), cached.outcome());

        AuthTokenVerifier.Result verificationResult = tokenVerifier.verify(authorizationHeader);
        if (!verificationResult.verified()) {
            return AuthVerificationResult.failed(verificationResult);
        }

        AuthResult authResult = validateSession(authorizationHeader, null, requestId, correlationId);
        if (!authResult.isAuthenticated()) {
            AuthResult fallbackAuthResult = buildLocalAuthResult(authorizationHeader);
            if (fallbackAuthResult == null || !fallbackAuthResult.isAuthenticated()) {
                return AuthVerificationResult.failed(verificationResult);
            }
            cacheAuthResult(cacheKey, fallbackAuthResult);
            return AuthVerificationResult.fromService(
                    AuthTokenVerifier.Result.verified("TOKEN_VERIFIED_LOCAL_FALLBACK"),
                    fallbackAuthResult
            );
        }

        cacheAuthResult(cacheKey, authResult);

        return AuthVerificationResult.fromService(verificationResult, authResult);
    }

    public AuthVerificationResult verifyCookie(String cookieHeader, String requestId, String correlationId) throws IOException, InterruptedException {
        if (!hasSessionCookie(cookieHeader)) {
            return AuthVerificationResult.failed(AuthTokenVerifier.Result.rejected("MISSING_SSO_SESSION_COOKIE"));
        }
        AuthResult authResult = validateSession(null, cookieHeader, requestId, correlationId);
        if (!authResult.isAuthenticated()) {
            AuthResult redisSessionAuthResult = buildRedisSessionAuthResult(cookieHeader);
            if (redisSessionAuthResult != null && redisSessionAuthResult.isAuthenticated()) {
                return AuthVerificationResult.fromService(
                        AuthTokenVerifier.Result.verified("COOKIE_SESSION_REDIS_FALLBACK"),
                        redisSessionAuthResult
                );
            }
            String accessToken = extractAccessTokenFromCookie(cookieHeader);
            if (accessToken == null || accessToken.isBlank()) {
                return AuthVerificationResult.failed(AuthTokenVerifier.Result.rejected("COOKIE_SESSION_UNAUTHORIZED"));
            }
            return verifyBearer("Bearer " + accessToken, requestId, correlationId);
        }
        return AuthVerificationResult.fromService(AuthTokenVerifier.Result.skipped("COOKIE_SESSION_VALIDATED"), authResult);
    }

    public String exchangeBasicForBearer(String authorizationHeader, String requestId, String correlationId) throws IOException, InterruptedException {
        return authServiceClient.exchangeBasicForBearer(authServiceUri, authorizationHeader, requestId, correlationId);
    }

    private CachedAuth loadCachedAuthResult(String cacheKey) {
        AuthResult cached = localCache.get(cacheKey);
        if (cached != null) {
            return new CachedAuth(cached, "SESSION_CACHE_L1");
        }

        if (redisCache == null || !redisCache.enabled()) {
            return null;
        }

        try {
            cached = redisCache.get(cacheKey);
        } catch (IOException ex) {
            log.log(Level.FINE, "redis session cache read failed", ex);
            return null;
        }
        if (cached != null) {
            localCache.put(cacheKey, cached);
            return new CachedAuth(cached, "SESSION_CACHE_L2");
        }
        return null;
    }

    private void cacheAuthResult(String cacheKey, AuthResult authResult) {
        localCache.put(cacheKey, authResult);
        if (redisCache == null || !redisCache.enabled()) {
            return;
        }

        try {
            redisCache.put(cacheKey, authResult);
        } catch (IOException ex) {
            log.log(Level.FINE, "redis session cache write failed", ex);
        }
    }

    private AuthResult validateSession(String authorizationHeader, String cookieHeader, String requestId, String correlationId) throws IOException, InterruptedException {
        return authServiceClient.validateSession(authServiceUri, authorizationHeader, cookieHeader, requestId, correlationId);
    }

    private static boolean hasSessionCookie(String cookieHeader) {
        return cookieHeader != null && !cookieHeader.isBlank() && cookieHeader.contains("sso_session=");
    }

    private AuthResult buildLocalAuthResult(String authorizationHeader) {
        AuthTokenVerifier.TokenClaims claims = tokenVerifier.parseClaims(authorizationHeader);
        if (claims == null || claims.userId() == null || claims.userId().isBlank()) {
            return null;
        }
        return new AuthResult(
                200,
                true,
                claims.userId(),
                claims.role(),
                claims.status(),
                "",
                claims.email(),
                claims.name(),
                claims.avatarUrl()
        );
    }

    private static String extractAccessTokenFromCookie(String cookieHeader) {
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return null;
        }
        String[] parts = cookieHeader.split(";");
        for (String part : parts) {
            String trimmed = part.trim();
            if (!trimmed.startsWith("ACCESS_TOKEN=")) {
                continue;
            }
            String value = trimmed.substring("ACCESS_TOKEN=".length()).trim();
            return value.isEmpty() ? null : value;
        }
        return null;
    }

    private AuthResult buildRedisSessionAuthResult(String cookieHeader) throws IOException {
        if (redisSsoSessionStore == null) {
            return null;
        }
        String sessionId = extractCookieValue(cookieHeader, "sso_session");
        if (sessionId == null || sessionId.isBlank()) {
            return null;
        }
        return redisSsoSessionStore.get(sessionId);
    }

    private static String extractCookieValue(String cookieHeader, String cookieName) {
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return null;
        }
        String[] parts = cookieHeader.split(";");
        String prefix = cookieName + "=";
        for (String part : parts) {
            String trimmed = part.trim();
            if (!trimmed.startsWith(prefix)) {
                continue;
            }
            String value = trimmed.substring(prefix.length()).trim();
            return value.isEmpty() ? null : value;
        }
        return null;
    }

    private record CachedAuth(AuthResult authResult, String outcome) {
    }

    private static String extractToken(String authorizationHeader) {
        if (authorizationHeader == null) return "";
        if (authorizationHeader.isBlank()) return "";
        if (!authorizationHeader.startsWith("Bearer ")) return "";
        return authorizationHeader.substring("Bearer ".length()).trim();
    }
}
