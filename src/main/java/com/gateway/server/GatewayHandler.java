package com.gateway.server;

import com.gateway.contract.InternalServiceApi;
import com.gateway.contract.external.path.AuthApiPaths;
import com.gateway.contract.external.path.HealthApiPaths;
import com.gateway.contract.internal.header.ServiceHeaders;
import com.gateway.audit.GatewayAuditService;
import com.gateway.code.GatewayErrorCode;
import com.gateway.config.GatewayConfig;
import com.gateway.contract.internal.header.TraceHeaders;
import com.gateway.exception.GatewayException;
import com.gateway.exception.GatewayExceptionHandler;
import com.gateway.http.ExchangeAdapter;
import com.gateway.http.Jsons;
import com.gateway.http.TrustedHeaderNames;
import com.gateway.auth.AuthResult;
import com.gateway.cache.LocalSessionCache;
import com.gateway.cache.RedisSessionCache;
import com.gateway.policy.CorsPolicy;
import com.gateway.policy.RequestWindowRateLimiter;
import com.gateway.policy.SecurityHeadersPolicy;
import com.gateway.proxy.ProxyRequest;
import com.gateway.proxy.ProxyResponse;
import com.gateway.proxy.ReverseProxyClient;
import com.gateway.routing.RouteMatch;
import com.gateway.routing.RouteResolver;
import com.gateway.routing.RouteType;
import com.gateway.security.AuthTokenVerifier;
import com.gateway.security.InternalJwtIssuer;
import com.gateway.security.JwtUserContextExtractor;
import com.gateway.security.JwtPrecheckPolicy;
import com.gateway.security.SessionCacheKey;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.logging.Level;
import java.util.logging.Logger;

/** 문서 설계 기준의 정책형 API Gateway 진입 핸들러입니다. */
public final class GatewayHandler implements HttpHandler {
    private static final Logger log = Logger.getLogger(GatewayHandler.class.getName());

    private final GatewayConfig config;
    private final RouteResolver routeResolver;
    private final ReverseProxyClient proxyClient;
    private final CorsPolicy corsPolicy;
    private final SecurityHeadersPolicy securityHeadersPolicy;
    private final RequestWindowRateLimiter loginRateLimiter;
    private final JwtPrecheckPolicy jwtPrecheckPolicy;
    private final AuthTokenVerifier tokenVerifier;
    private final JwtUserContextExtractor userContextExtractor;
    private final InternalJwtIssuer internalJwtIssuer;
    private final LocalSessionCache localSessionCache;
    private final RedisSessionCache redisSessionCache;
    private final GatewayAuditService gatewayAuditService;

    public GatewayHandler(GatewayConfig config) {
        this.config = config;
        this.routeResolver = new RouteResolver(config.routes());
        this.proxyClient = new ReverseProxyClient(config.requestTimeout());
        this.corsPolicy = new CorsPolicy(config.allowedOrigins());
        this.securityHeadersPolicy = new SecurityHeadersPolicy();
        this.loginRateLimiter = new RequestWindowRateLimiter(config.loginRateLimitPerMinute(), 60_000);
        this.jwtPrecheckPolicy = new JwtPrecheckPolicy(
                config.jwtPrecheckExpEnabled(),
                config.jwtPrecheckExpClockSkewSeconds(),
                config.jwtPrecheckMaxTokenLength()
        );
        this.tokenVerifier = new AuthTokenVerifier(
                config.authJwtVerifyEnabled(),
                config.authJwtPublicKeyPem(),
                config.authJwtSharedSecret(),
                config.authJwtKeyId(),
                config.authJwtAlgorithm(),
                config.authJwtIssuer(),
                config.authJwtAudience(),
                config.authJwtClockSkewSeconds()
        );
        this.userContextExtractor = new JwtUserContextExtractor(config.gatewayUserIdClaimNames());
        this.internalJwtIssuer = new InternalJwtIssuer(
                config.internalJwtSharedSecret(),
                config.internalJwtIssuer(),
                config.internalJwtAudience(),
                config.internalJwtTtlSeconds()
        );
        int localTtl = config.sessionCacheEnabled() ? config.sessionLocalCacheTtlSeconds() : 0;
        this.localSessionCache = new LocalSessionCache(localTtl);
        this.redisSessionCache = new RedisSessionCache(
                config.sessionCacheEnabled(),
                config.redisHost(),
                config.redisPort(),
                config.redisTimeoutMs(),
                config.sessionCacheTtlSeconds(),
                config.sessionCacheKeyPrefix()
        );
        this.gatewayAuditService = new GatewayAuditService(config);
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        long startedAt = System.currentTimeMillis();
        ExchangeAdapter adapter = new ExchangeAdapter(exchange);
        String requestId = resolveOrCreate(exchange.getRequestHeaders().getFirst(TraceHeaders.REQUEST_ID));
        String correlationId = resolveOrCreate(exchange.getRequestHeaders().getFirst(TraceHeaders.CORRELATION_ID));
        applyResponsePolicies(exchange, requestId, correlationId);

        String authOutcome = "FORWARDED";
        String resolvedUserId = "";
        String upstreamAuthorizationHeader = null;
        String requestPath = "/";
        String upstreamName = "gateway";
        String clientIp = "";
        String requestMethod = adapter.method();

        try {
            if (!isAllowedOrigin(exchange.getRequestHeaders().getFirst("Origin"))) throw new GatewayException(GatewayErrorCode.FORBIDDEN);

            if ("OPTIONS".equalsIgnoreCase(adapter.method())) {adapter.sendEmpty(204);
                return;
            }

            InetAddress clientAddress = adapter.remoteAddress().getAddress();
            clientIp = clientAddress.getHostAddress();

            requestPath = normalizePath(adapter.uri().getPath());
            if (isHealthPath(requestPath)) {
                adapter.sendJson(200, Jsons.toJson(Map.of("status", "UP")));
                return;
            }

            RouteMatch match = routeResolver.resolve(requestPath, adapter.uri().getRawQuery());
            if (match == null) throw new GatewayException(GatewayErrorCode.NOT_FOUND);
            upstreamName = match.route().upstreamName();

            RouteType routeType = match.route().routeType();

            if (routeType == RouteType.INTERNAL && !isInternalRequestAllowed(exchange)) throw new GatewayException(GatewayErrorCode.FORBIDDEN);
            if (shouldApplyGatewayIpGuard(routeType) && !config.adminIpPolicy().allows(clientIp)) throw new GatewayException(GatewayErrorCode.FORBIDDEN);
            if (isLoginPath(requestPath) && !loginRateLimiter.allow(clientIp)) throw new GatewayException(GatewayErrorCode.TOO_MANY_REQUESTS);

            if (requiresAuthorizationPrecheck(match.route(), requestPath)) {
                String authForVerification = resolveIncomingAuth(exchange);
                JwtPrecheckPolicy.Result precheckResult = jwtPrecheckPolicy.precheck(authForVerification);
                authOutcome = precheckResult.outcome();
                if (!precheckResult.accepted()) throw new GatewayException(GatewayErrorCode.UNAUTHORIZED);

                String token = extractToken(authForVerification);
                String cacheKey = SessionCacheKey.fromToken(token);
                AuthResult cachedAuthResult = localSessionCache.get(cacheKey);
                if (cachedAuthResult != null && cachedAuthResult.isAuthenticated() && hasUserId(cachedAuthResult)) {
                    resolvedUserId = cachedAuthResult.getUserId();
                    authOutcome = "SESSION_CACHE_L1";
                } else {
                    if (redisSessionCache.enabled()) {
                        try {
                            cachedAuthResult = redisSessionCache.get(cacheKey);
                        } catch (IOException ex) {
                            log.log(Level.FINE, "requestId=" + requestId + " redis_session_cache_read_failed", ex);
                            cachedAuthResult = null;
                        }
                        if (cachedAuthResult != null && cachedAuthResult.isAuthenticated() && hasUserId(cachedAuthResult)) {
                            localSessionCache.put(cacheKey, cachedAuthResult);
                            resolvedUserId = cachedAuthResult.getUserId();
                            authOutcome = "SESSION_CACHE_L2";
                        }
                    }
                }

                if (resolvedUserId == null || resolvedUserId.isBlank()) {
                    AuthTokenVerifier.Result verificationResult = tokenVerifier.verify(authForVerification);
                    authOutcome = verificationResult.outcome();
                    if (!verificationResult.verified()) throw new GatewayException(GatewayErrorCode.UNAUTHORIZED);

                    resolvedUserId = userContextExtractor.extractUserId(authForVerification);
                    if (resolvedUserId == null || resolvedUserId.isBlank()) {
                        throw new GatewayException(GatewayErrorCode.UNAUTHORIZED);
                    }

                    AuthResult verifiedAuthResult = new AuthResult(200, true, resolvedUserId, null, null);
                    localSessionCache.put(cacheKey, verifiedAuthResult);
                    if (redisSessionCache.enabled()) {
                        try {
                            redisSessionCache.put(cacheKey, verifiedAuthResult);
                        } catch (IOException ex) {
                            log.log(Level.FINE, "requestId=" + requestId + " redis_session_cache_write_failed", ex);
                        }
                    }
                }

                upstreamAuthorizationHeader = internalJwtIssuer.issueForUser(resolvedUserId);
            }

            enforceBodySize(exchange);

            Map<String, List<String>> proxiedHeaders = sanitizeInboundHeaders(exchange, match.route());
            proxiedHeaders.put(TraceHeaders.REQUEST_ID, List.of(requestId));
            proxiedHeaders.put(TraceHeaders.CORRELATION_ID, List.of(correlationId));
            injectTrustedContext(proxiedHeaders, resolvedUserId);
            injectUpstreamAuthorization(proxiedHeaders, upstreamAuthorizationHeader);

            byte[] requestBody = adapter.readBody();
            ProxyRequest proxyRequest = new ProxyRequest(
                    adapter.method(),
                    match.targetUri(),
                    proxiedHeaders,
                    requestBody,
                    clientIp
            );
            logOAuthRequestTraceIfEnabled(exchange, requestPath, requestId, correlationId, proxyRequest);

            ProxyResponse proxyResponse = proxyClient.forward(proxyRequest);
            if ("FORWARDED".equals(authOutcome)) {
                authOutcome = "PRECHECK_BYPASSED";
            }
            logOAuthResponseTraceIfEnabled(requestPath, requestId, correlationId, proxyRequest, proxyResponse);
            applyResponsePolicies(exchange, requestId, correlationId);
            adapter.sendStream(proxyResponse.getStatusCode(), proxyResponse.getHeaders(), proxyResponse.getBody());
            gatewayAuditService.logRequest(
                    requestMethod,
                    requestPath,
                    requestId,
                    clientIp,
                    resolvedUserId,
                    upstreamName,
                    proxyResponse.getStatusCode(),
                    authOutcome,
                    null
            );
        } catch (GatewayException ex) {
            GatewayExceptionHandler.ResponseSpec responseSpec = GatewayExceptionHandler.handleGatewayException(ex, requestPath, requestId);
            gatewayAuditService.logRequest(
                    requestMethod,
                    requestPath,
                    requestId,
                    clientIp,
                    resolvedUserId,
                    upstreamName,
                    responseSpec.httpStatus(),
                    authOutcome,
                    ex.getErrorCode().getCode()
            );
            adapter.sendJson(responseSpec.httpStatus(), responseSpec.jsonBody());
        } catch (IllegalStateException ex) {
            GatewayExceptionHandler.ResponseSpec responseSpec =
                    GatewayExceptionHandler.fromErrorCode(GatewayErrorCode.PAYLOAD_TOO_LARGE, requestPath, requestId);
            gatewayAuditService.logRequest(
                    requestMethod,
                    requestPath,
                    requestId,
                    clientIp,
                    resolvedUserId,
                    upstreamName,
                    responseSpec.httpStatus(),
                    authOutcome,
                    GatewayErrorCode.PAYLOAD_TOO_LARGE.getCode()
            );
            adapter.sendJson(responseSpec.httpStatus(), responseSpec.jsonBody());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            GatewayExceptionHandler.ResponseSpec responseSpec =
                    GatewayExceptionHandler.fromErrorCode(GatewayErrorCode.UPSTREAM_TIMEOUT, requestPath, requestId);
            gatewayAuditService.logRequest(
                    requestMethod,
                    requestPath,
                    requestId,
                    clientIp,
                    resolvedUserId,
                    upstreamName,
                    responseSpec.httpStatus(),
                    authOutcome,
                    GatewayErrorCode.UPSTREAM_TIMEOUT.getCode()
            );
            adapter.sendJson(responseSpec.httpStatus(), responseSpec.jsonBody());
        } catch (IOException ex) {
            GatewayExceptionHandler.ResponseSpec responseSpec =
                    GatewayExceptionHandler.fromErrorCode(GatewayErrorCode.UPSTREAM_FAILURE, requestPath, requestId);
            gatewayAuditService.logRequest(
                    requestMethod,
                    requestPath,
                    requestId,
                    clientIp,
                    resolvedUserId,
                    upstreamName,
                    responseSpec.httpStatus(),
                    authOutcome,
                    GatewayErrorCode.UPSTREAM_FAILURE.getCode()
            );
            adapter.sendJson(responseSpec.httpStatus(), responseSpec.jsonBody());
        } catch (IllegalArgumentException ex) {
            GatewayExceptionHandler.ResponseSpec responseSpec =
                    GatewayExceptionHandler.handleIllegalArgumentException(ex, requestPath, requestId);
            gatewayAuditService.logRequest(
                    requestMethod,
                    requestPath,
                    requestId,
                    clientIp,
                    resolvedUserId,
                    upstreamName,
                    responseSpec.httpStatus(),
                    authOutcome,
                    GatewayErrorCode.INVALID_REQUEST.getCode()
            );
            adapter.sendJson(responseSpec.httpStatus(), responseSpec.jsonBody());
        } catch (java.lang.Exception ex) {
            GatewayExceptionHandler.ResponseSpec responseSpec =
                    GatewayExceptionHandler.handleException(ex, requestPath, requestId);
            gatewayAuditService.logRequest(
                    requestMethod,
                    requestPath,
                    requestId,
                    clientIp,
                    resolvedUserId,
                    upstreamName,
                    responseSpec.httpStatus(),
                    authOutcome,
                    GatewayErrorCode.INTERNAL_ERROR.getCode()
            );
            adapter.sendJson(responseSpec.httpStatus(), responseSpec.jsonBody());
        } finally {
            adapter.close();
        }
    }

    private void enforceBodySize(HttpExchange exchange) {
        String contentLength = exchange.getRequestHeaders().getFirst("Content-Length");
        if (contentLength == null || contentLength.isBlank()) {
            return;
        }
        try {
            long size = Long.parseLong(contentLength.trim());
            if (size > config.maxBodyBytes()) {
                throw new IllegalStateException("Request body exceeds gateway limit");
            }
        } catch (NumberFormatException ignored) {
        }
    }

    private void applyResponsePolicies(HttpExchange exchange, String requestId, String correlationId) {
        corsPolicy.apply(exchange.getRequestHeaders().getFirst("Origin"), exchange.getResponseHeaders());
        securityHeadersPolicy.apply(exchange.getResponseHeaders());
        exchange.getResponseHeaders().set(TraceHeaders.REQUEST_ID, requestId);
        exchange.getResponseHeaders().set(TraceHeaders.CORRELATION_ID, correlationId);
    }

    private boolean isAllowedOrigin(String origin) {
        return origin == null || origin.isBlank() || corsPolicy.isOriginAllowed(origin);
    }

    private boolean isHealthPath(String path) {
        return HealthApiPaths.HEALTH.equals(path) || HealthApiPaths.READY.equals(path);
    }

    private boolean isLoginPath(String path) {
        return AuthApiPaths.LOGIN.equals(path)
                || AuthApiPaths.SSO_START.equals(path)
                || path.startsWith("/v1/auth/oauth2/authorize/")
                || path.startsWith("/v1/oauth2/authorization/");
    }

    private boolean shouldApplyGatewayIpGuard(RouteType routeType) {
        return routeType == RouteType.ADMIN;
    }

    private boolean isInternalRequestAllowed(HttpExchange exchange) {
        String provided = exchange.getRequestHeaders().getFirst(ServiceHeaders.Auth.INTERNAL_REQUEST_SECRET);
        String expected = config.internalRequestSecret();
        if (expected == null || expected.isBlank()) {
            return false;
        }
        return expected.equals(provided);
    }

    private String normalizePath(String path) {
        if (path == null || path.isBlank()) {
            return "/";
        }
        if (path.length() > 1 && path.endsWith("/")) {
            return path.substring(0, path.length() - 1);
        }
        return path;
    }

    private String resolveOrCreate(String headerValue) {
        return (headerValue == null || headerValue.isBlank()) ? UUID.randomUUID().toString() : headerValue;
    }

    private boolean requiresAuthorizationPrecheck(com.gateway.routing.RouteDefinition route, String path) {
        return route.routeType() == RouteType.PROTECTED || route.routeType() == RouteType.ADMIN;
    }

    private boolean hasBearerToken(String authorizationHeader) {
        return authorizationHeader != null
                && !authorizationHeader.isBlank()
                && authorizationHeader.startsWith("Bearer ");
    }

    private String resolveIncomingAuth(HttpExchange exchange) {
        String authorizationHeader = exchange.getRequestHeaders().getFirst("Authorization");
        if (hasBearerToken(authorizationHeader)) {
            return authorizationHeader;
        }
        String accessToken = extractCookieValue(exchange.getRequestHeaders().getFirst("Cookie"), "ACCESS_TOKEN");
        if (accessToken == null || accessToken.isBlank()) {
            accessToken = extractCookieValue(exchange.getRequestHeaders().getFirst("Cookie"), "sso_session");
        }
        if (accessToken == null || accessToken.isBlank()) {
            return null;
        }
        return "Bearer " + accessToken;
    }

    private static String extractToken(String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return "";
        }
        if (!authorizationHeader.startsWith("Bearer ")) {
            return "";
        }
        return authorizationHeader.substring("Bearer ".length()).trim();
    }

    private static boolean hasUserId(AuthResult authResult) {
        return authResult.getUserId() != null && !authResult.getUserId().isBlank();
    }

    private String extractCookieValue(String cookieHeader, String cookieName) {
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return null;
        }
        String[] pairs = cookieHeader.split(";");
        for (String pair : pairs) {
            String trimmed = pair.trim();
            int idx = trimmed.indexOf('=');
            if (idx <= 0) {
                continue;
            }
            String name = trimmed.substring(0, idx).trim();
            if (!cookieName.equals(name)) {
                continue;
            }
            String value = trimmed.substring(idx + 1).trim();
            if (value.isBlank()) {
                return null;
            }
            return value;
        }
        return null;
    }

    private Map<String, List<String>> sanitizeInboundHeaders(HttpExchange exchange, com.gateway.routing.RouteDefinition route) {
        Map<String, List<String>> sanitized = exchange.getRequestHeaders().entrySet().stream()
                .filter(entry -> !TrustedHeaderNames.ALL.contains(entry.getKey().toLowerCase()))
                .collect(java.util.stream.Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> new ArrayList<>(entry.getValue())
                ));
        if (!shouldForwardAuthorizationHeader(route)) {
            sanitized.entrySet().removeIf(entry -> "authorization".equalsIgnoreCase(entry.getKey()));
        }
        return sanitized;
    }

    private boolean shouldForwardAuthorizationHeader(com.gateway.routing.RouteDefinition route) {
        if ("user".equals(route.upstreamName()) || "auth".equals(route.upstreamName())) {
            return true;
        }
        return config.forwardAuthorizationHeader();
    }

    private void injectTrustedContext(Map<String, List<String>> proxiedHeaders, String resolvedUserId) {
        if (resolvedUserId == null || resolvedUserId.isBlank()) {
            return;
        }
        proxiedHeaders.put(InternalServiceApi.Headers.USER_ID, List.of(resolvedUserId));
    }

    private void injectUpstreamAuthorization(Map<String, List<String>> proxiedHeaders, String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return;
        }
        proxiedHeaders.entrySet().removeIf(entry -> "authorization".equalsIgnoreCase(entry.getKey()));
        proxiedHeaders.put("Authorization", List.of(authorizationHeader));
    }

    private void logOAuthRequestTraceIfEnabled(
            HttpExchange exchange,
            String requestPath,
            String requestId,
            String correlationId,
            ProxyRequest proxyRequest
    ) {
        if (!config.oauthDebugLogEnabled() || !isOAuthFlowPath(requestPath)) {
            return;
        }
        String rawQuery = exchange.getRequestURI().getRawQuery();
        String cookieHeader = exchange.getRequestHeaders().getFirst("Cookie");
        boolean hasAuthorization = hasBearerToken(exchange.getRequestHeaders().getFirst("Authorization"));
        log.info("oauth_trace request"
                + " requestId=" + requestId
                + " correlationId=" + correlationId
                + " method=" + exchange.getRequestMethod()
                + " path=" + requestPath
                + " targetUri=" + proxyRequest.getTargetUri()
                + " hasCodeParam=" + containsQueryParam(rawQuery, "code")
                + " hasStateParam=" + containsQueryParam(rawQuery, "state")
                + " hasCookie=" + (cookieHeader != null && !cookieHeader.isBlank())
                + " cookieNames=" + summarizeCookieNames(cookieHeader)
                + " hasBearerAuth=" + hasAuthorization);
    }

    private void logOAuthResponseTraceIfEnabled(
            String requestPath,
            String requestId,
            String correlationId,
            ProxyRequest proxyRequest,
            ProxyResponse proxyResponse
    ) {
        if (!config.oauthDebugLogEnabled() || !isOAuthFlowPath(requestPath)) {
            return;
        }
        String location = firstHeaderValue(proxyResponse.getHeaders(), "Location");
        List<String> setCookies = headerValues(proxyResponse.getHeaders(), "Set-Cookie");
        log.info("oauth_trace response"
                + " requestId=" + requestId
                + " correlationId=" + correlationId
                + " path=" + requestPath
                + " targetUri=" + proxyRequest.getTargetUri()
                + " status=" + proxyResponse.getStatusCode()
                + " location=" + safeText(location)
                + " setCookieCount=" + setCookies.size());
    }

    private boolean isOAuthFlowPath(String path) {
        return AuthApiPaths.SSO_START.equals(path)
                || AuthApiPaths.EXCHANGE.equals(path)
                || path.startsWith("/v1/oauth2/")
                || path.startsWith("/v1/login/oauth2/");
    }

    private boolean containsQueryParam(String rawQuery, String name) {
        if (rawQuery == null || rawQuery.isBlank()) {
            return false;
        }
        String prefix = name + "=";
        for (String token : rawQuery.split("&")) {
            if (token.equals(name) || token.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private String summarizeCookieNames(String cookieHeader) {
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return "-";
        }
        String joined = java.util.Arrays.stream(cookieHeader.split(";"))
                .map(String::trim)
                .filter(part -> !part.isBlank())
                .map(part -> {
                    int idx = part.indexOf('=');
                    return idx > 0 ? part.substring(0, idx).trim() : part;
                })
                .filter(name -> !name.isBlank())
                .distinct()
                .collect(Collectors.joining(","));
        return joined.isBlank() ? "-" : joined;
    }

    private String safeText(String value) {
        return (value == null || value.isBlank()) ? "-" : value;
    }

    private String firstHeaderValue(Map<String, List<String>> headers, String headerName) {
        return headers.entrySet().stream()
                .filter(entry -> headerName.equalsIgnoreCase(entry.getKey()))
                .findFirst()
                .map(Map.Entry::getValue)
                .filter(values -> !values.isEmpty())
                .map(values -> values.get(0))
                .orElse(null);
    }

    private List<String> headerValues(Map<String, List<String>> headers, String headerName) {
        return headers.entrySet().stream()
                .filter(entry -> headerName.equalsIgnoreCase(entry.getKey()))
                .findFirst()
                .map(Map.Entry::getValue)
                .orElse(List.of());
    }
}
