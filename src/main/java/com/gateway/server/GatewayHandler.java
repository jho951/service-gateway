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
import com.gateway.contract.external.header.ExternalApiHeaders;
import com.gateway.policy.CorsPolicy;
import com.gateway.policy.RequestWindowRateLimiter;
import com.gateway.policy.SecurityHeadersPolicy;
import com.gateway.proxy.ProxyRequest;
import com.gateway.proxy.ProxyResponse;
import com.gateway.proxy.ReverseProxyClient;
import com.gateway.routing.RouteMatch;
import com.gateway.routing.RouteResolver;
import com.gateway.routing.RouteType;
import com.gateway.security.AuthVerificationResult;
import com.gateway.security.AuthSessionValidator;
import com.gateway.security.InternalJwtIssuer;
import com.gateway.security.RequestChannel;
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
    private final AuthSessionValidator authSessionValidator;
    private final InternalJwtIssuer internalJwtIssuer;
    private final GatewayAuditService gatewayAuditService;

    /**
     * 생성자
     * @param config
     */
    public GatewayHandler(GatewayConfig config) {
        this.config = config;
        this.routeResolver = new RouteResolver(config.routes());
        this.proxyClient = new ReverseProxyClient(config.requestTimeout());
        this.corsPolicy = new CorsPolicy(config.allowedOrigins());
        this.securityHeadersPolicy = new SecurityHeadersPolicy();
        this.loginRateLimiter = new RequestWindowRateLimiter(config.loginRateLimitPerMinute(), 60_000);
        this.internalJwtIssuer = new InternalJwtIssuer(
                config.internalJwtSharedSecret(),
                config.internalJwtIssuer(),
                config.internalJwtAudience(),
                config.internalJwtTtlSeconds()
        );
        this.authSessionValidator = new AuthSessionValidator(
                config.authServiceUri(),
                new com.gateway.security.JwtPrecheckPolicy(
                        config.jwtPrecheckExpEnabled(),
                        config.jwtPrecheckExpClockSkewSeconds(),
                        config.jwtPrecheckMaxTokenLength()
                ),
                new com.gateway.security.AuthTokenVerifier(
                        config.authJwtVerifyEnabled(),
                        config.authJwtPublicKeyPem(),
                        config.authJwtSharedSecret(),
                        config.authJwtKeyId(),
                        config.authJwtAlgorithm(),
                        config.authJwtIssuer(),
                        config.authJwtAudience(),
                        config.authJwtClockSkewSeconds()
                ),
                new com.gateway.auth.AuthServiceClient(config.requestTimeout()),
                new com.gateway.cache.LocalSessionCache(config.sessionCacheEnabled() ? config.sessionLocalCacheTtlSeconds() : 0),
                new com.gateway.cache.RedisSessionCache(
                        config.sessionCacheEnabled(),
                        config.redisHost(),
                        config.redisPort(),
                        config.redisPassword(),
                        config.redisTimeoutMs(),
                        config.sessionCacheTtlSeconds(),
                        config.sessionCacheKeyPrefix()
                )
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
        String resolvedUserStatus = "";
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
                AuthContext authContext = authenticateProtectedRequest(exchange, match, requestPath, requestId, correlationId);
                resolvedUserId = authContext.userId();
                resolvedUserStatus = authContext.userStatus();
                authOutcome = authContext.authOutcome();
                upstreamAuthorizationHeader = internalJwtIssuer.issueForUser(resolvedUserId, resolvedUserStatus);
            }

            enforceBodySize(exchange);

            Map<String, List<String>> proxiedHeaders = sanitizeInboundHeaders(exchange, match.route());
            proxiedHeaders.put(TraceHeaders.REQUEST_ID, List.of(requestId));
            proxiedHeaders.put(TraceHeaders.CORRELATION_ID, List.of(correlationId));
            injectTrustedContext(proxiedHeaders, requestPath, match.route(), requestId, resolvedUserId, resolvedUserStatus, resolveRequestChannel(exchange, requestPath, match.route()));
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
            log.log(Level.WARNING,
                    "requestId=" + requestId
                            + " upstream_request_failed"
                            + " method=" + requestMethod
                            + " path=" + requestPath
                            + " upstream=" + upstreamName,
                    ex);
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
                || AuthApiPaths.SSO_START_LEGACY.equals(path)
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

    private String resolveIncomingAuth(RequestChannel requestChannel, HttpExchange exchange) {
        if (requestChannel == null) {
            return null;
        }
        if (requestChannel.isWeb()) {
            String cookieHeader = exchange.getRequestHeaders().getFirst("Cookie");
            String accessToken = extractCookieValue(cookieHeader, "ACCESS_TOKEN");
            if (accessToken != null && !accessToken.isBlank()) {
                return "Bearer " + accessToken;
            }
            return null;
        }
        String authorizationHeader = exchange.getRequestHeaders().getFirst("Authorization");
        if (hasBearerToken(authorizationHeader)) {
            return authorizationHeader;
        }
        return null;
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
        sanitized.entrySet().removeIf(entry -> "authorization".equalsIgnoreCase(entry.getKey()));
        return sanitized;
    }

    private void injectTrustedContext(
            Map<String, List<String>> proxiedHeaders,
            String requestPath,
            com.gateway.routing.RouteDefinition route,
            String requestId,
            String resolvedUserId,
            String resolvedUserStatus,
            RequestChannel requestChannel
    ) {
        if (resolvedUserId == null || resolvedUserId.isBlank()) {
            return;
        }
        proxiedHeaders.put(InternalServiceApi.Headers.USER_ID, List.of(resolvedUserId));
        if (resolvedUserStatus != null && !resolvedUserStatus.isBlank()) {
            proxiedHeaders.put(InternalServiceApi.Headers.USER_STATUS, List.of(resolvedUserStatus));
        }
        if (requestChannel != null) {
            proxiedHeaders.put(InternalServiceApi.Headers.CLIENT_TYPE, List.of(requestChannel.headerValue()));
        }
        if (route.routeType() == RouteType.PROTECTED || route.routeType() == RouteType.ADMIN) {
            log.info("trusted_context_injected"
                    + " requestId=" + requestId
                    + " path=" + requestPath
                    + " upstream=" + route.upstreamName()
                    + " channel=" + (requestChannel == null ? "unknown" : requestChannel.headerValue())
                    + " userId=" + resolvedUserId
                    + " userStatus=" + resolveUserStatus(resolvedUserStatus)
                    + " headers=[" + InternalServiceApi.Headers.USER_ID + ", "
                    + InternalServiceApi.Headers.USER_STATUS + ", "
                    + InternalServiceApi.Headers.CLIENT_TYPE + "]");
        }
    }

    private String resolveUserStatus(String status) {
        if (status == null || status.isBlank()) {
            return "A";
        }
        return status;
    }

    private void injectUpstreamAuthorization(Map<String, List<String>> proxiedHeaders, String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return;
        }
        proxiedHeaders.entrySet().removeIf(entry -> "authorization".equalsIgnoreCase(entry.getKey()));
        proxiedHeaders.put("Authorization", List.of(authorizationHeader));
    }

    private RequestChannel resolveRequestChannel(HttpExchange exchange, String requestPath, com.gateway.routing.RouteDefinition route) {
        String clientTypeHeader = exchange.getRequestHeaders().getFirst(ExternalApiHeaders.CLIENT_TYPE);
        RequestChannel fromClientType = RequestChannel.fromClientType(clientTypeHeader);
        if (clientTypeHeader != null && !clientTypeHeader.isBlank() && fromClientType == null) {
            throw new GatewayException(GatewayErrorCode.INVALID_CLIENT_TYPE);
        }
        if (fromClientType != null) {
            return fromClientType;
        }

        String origin = exchange.getRequestHeaders().getFirst("Origin");
        if (origin != null && !origin.isBlank()) {
            return RequestChannel.WEB;
        }

        String referer = exchange.getRequestHeaders().getFirst("Referer");
        if (referer != null && !referer.isBlank()) {
            return RequestChannel.WEB;
        }

        String userAgent = exchange.getRequestHeaders().getFirst("User-Agent");
        RequestChannel fromUserAgent = resolveRequestChannelFromUserAgent(userAgent);
        if (fromUserAgent != null) {
            return fromUserAgent;
        }

        RequestChannel endpointChannel = resolveRequestChannelFromEndpoint(requestPath, route);
        if (endpointChannel == null) {
            throw new GatewayException(GatewayErrorCode.INVALID_REQUEST_CHANNEL);
        }
        return endpointChannel;
    }

    private RequestChannel resolveRequestChannelFromUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return null;
        }
        String normalized = userAgent.toLowerCase(java.util.Locale.ROOT);
        if (normalized.contains("curl")
                || normalized.contains("wget")
                || normalized.contains("httpie")
                || normalized.contains("postman")
                || normalized.contains("python-requests")) {
            return RequestChannel.CLI;
        }
        if (normalized.contains("okhttp")
                || normalized.contains("retrofit")
                || normalized.contains("apollo")
                || normalized.contains("dart")
                || normalized.contains("dio")
                || normalized.contains("mobile")
                || normalized.contains("android")
                || normalized.contains("iphone")
                || normalized.contains("ios")) {
            return RequestChannel.NATIVE;
        }
        if (normalized.contains("mozilla")
                || normalized.contains("chrome")
                || normalized.contains("safari")
                || normalized.contains("firefox")
                || normalized.contains("edge")) {
            return RequestChannel.WEB;
        }
        return RequestChannel.API;
    }

    private RequestChannel resolveRequestChannelFromEndpoint(String requestPath, com.gateway.routing.RouteDefinition route) {
        if (route.routeType() != RouteType.PROTECTED && route.routeType() != RouteType.ADMIN) {
            return null;
        }
        if (requestPath == null || requestPath.isBlank()) {
            return RequestChannel.WEB;
        }
        if (requestPath.startsWith("/v1/documents/")
                || requestPath.equals("/v1/documents")
                || requestPath.startsWith("/v1/admin/")
                || requestPath.startsWith("/v1/users/me")) {
            return RequestChannel.WEB;
        }
        return RequestChannel.WEB;
    }

    private boolean hasCookieBasedAuth(String cookieHeader) {
        if (cookieHeader == null || cookieHeader.isBlank()) {
            return false;
        }
        return cookieHeader.contains("ACCESS_TOKEN=") || cookieHeader.contains("sso_session=");
    }

    private AuthContext authenticateProtectedRequest(
            HttpExchange exchange,
            RouteMatch match,
            String requestPath,
            String requestId,
            String correlationId
    ) throws IOException, InterruptedException {
        RequestChannel requestChannel = resolveRequestChannel(exchange, requestPath, match.route());
        String authForVerification = resolveIncomingAuth(requestChannel, exchange);
        if (authForVerification == null || authForVerification.isBlank()) {
            return authenticateMissingCredentials(exchange, requestChannel, requestId, correlationId);
        }

        AuthVerificationResult verificationResult = authSessionValidator.verifyBearer(authForVerification, requestId, correlationId);
        AuthResult authResult = verificationResult.authResult();
        if (!verificationResult.verified() || authResult == null || !hasUserId(authResult)) {
            throw new GatewayException(GatewayErrorCode.UNAUTHORIZED);
        }

        String userStatus = resolveUserStatus(authResult.getStatus());
        if (userStatus == null || userStatus.isBlank()) {
            userStatus = "A";
        }
        return new AuthContext(authResult.getUserId(), userStatus, verificationResult.outcome());
    }

    private AuthContext authenticateMissingCredentials(
            HttpExchange exchange,
            RequestChannel requestChannel,
            String requestId,
            String correlationId
    ) throws IOException, InterruptedException {
        if (requestChannel.isWeb()) {
            String cookieHeader = exchange.getRequestHeaders().getFirst("Cookie");
            if (cookieHeader == null || cookieHeader.isBlank() || !cookieHeader.contains("sso_session=")) {
                if (hasBearerToken(exchange.getRequestHeaders().getFirst("Authorization"))) {
                    throw new GatewayException(GatewayErrorCode.AUTH_CHANNEL_MISMATCH);
                }
                throw new GatewayException(GatewayErrorCode.MISSING_AUTH_CREDENTIALS);
            }
            AuthVerificationResult sessionVerificationResult = authSessionValidator.verifyCookie(
                    cookieHeader,
                    requestId,
                    correlationId
            );
            AuthResult sessionAuthResult = sessionVerificationResult.authResult();
            if (!sessionVerificationResult.verified() || sessionAuthResult == null || !hasUserId(sessionAuthResult)) {
                throw new GatewayException(GatewayErrorCode.UNAUTHORIZED);
            }
            String userStatus = resolveUserStatus(sessionAuthResult.getStatus());
            if (userStatus == null || userStatus.isBlank()) {
                userStatus = "A";
            }
            return new AuthContext(sessionAuthResult.getUserId(), userStatus, sessionVerificationResult.outcome());
        }

        if (hasCookieBasedAuth(exchange.getRequestHeaders().getFirst("Cookie"))) {
            throw new GatewayException(GatewayErrorCode.AUTH_CHANNEL_MISMATCH);
        }
        throw new GatewayException(GatewayErrorCode.MISSING_AUTH_CREDENTIALS);
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
                || AuthApiPaths.SSO_START_LEGACY.equals(path)
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

    private record AuthContext(String userId, String userStatus, String authOutcome) {
    }
}
