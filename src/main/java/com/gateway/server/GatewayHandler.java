package com.gateway.server;

import com.gateway.api.GatewayApiPaths;
import com.gateway.api.InternalServiceApi;
import com.gateway.auth.AuthResult;
import com.gateway.auth.AuthServiceClient;
import com.gateway.auth.AuthValidationCache;
import com.gateway.auth.PermissionServiceClient;
import com.gateway.cache.RedisPermissionCache;
import com.gateway.code.ErrorCode;
import com.gateway.code.SuccessCode;
import com.gateway.config.GatewayConfig;
import com.gateway.dto.GlobalResponse;
import com.gateway.exception.GlobalException;
import com.gateway.exception.GlobalExceptionHandler;
import com.gateway.http.ExchangeAdapter;
import com.gateway.http.Jsons;
import com.gateway.http.TrustedHeaderNames;
import com.gateway.policy.CorsPolicy;
import com.gateway.policy.RequestWindowRateLimiter;
import com.gateway.policy.SecurityHeadersPolicy;
import com.gateway.proxy.ProxyRequest;
import com.gateway.proxy.ProxyResponse;
import com.gateway.proxy.ReverseProxyClient;
import com.gateway.routing.RouteMatch;
import com.gateway.routing.RouteResolver;
import com.gateway.routing.RouteType;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/** 문서 설계 기준의 정책형 API Gateway 진입 핸들러입니다. */
public final class GatewayHandler implements HttpHandler {
    private static final Logger log = Logger.getLogger(GatewayHandler.class.getName());

    private final GatewayConfig config;
    private final RouteResolver routeResolver;
    private final AuthServiceClient authServiceClient;
    private final PermissionServiceClient permissionServiceClient;
    private final AuthValidationCache authValidationCache;
    private final ReverseProxyClient proxyClient;
    private final CorsPolicy corsPolicy;
    private final SecurityHeadersPolicy securityHeadersPolicy;
    private final RequestWindowRateLimiter loginRateLimiter;
    private final RedisPermissionCache permissionCache;

    public GatewayHandler(GatewayConfig config) {
        this.config = config;
        this.routeResolver = new RouteResolver(config.routes());
        this.authServiceClient = new AuthServiceClient(config.authTimeout());
        this.permissionServiceClient = new PermissionServiceClient(config.authTimeout());
        this.authValidationCache = new AuthValidationCache(config.authCacheTtl());
        this.proxyClient = new ReverseProxyClient(config.requestTimeout());
        this.corsPolicy = new CorsPolicy(config.allowedOrigins());
        this.securityHeadersPolicy = new SecurityHeadersPolicy();
        this.loginRateLimiter = new RequestWindowRateLimiter(config.loginRateLimitPerMinute(), 60_000);
        this.permissionCache = new RedisPermissionCache(
                config.permissionCacheEnabled(),
                config.redisHost(),
                config.redisPort(),
                config.redisTimeoutMs(),
                config.permissionCacheTtlSeconds(),
                config.permissionCacheKeyPrefix()
        );
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        long startedAt = System.currentTimeMillis();
        ExchangeAdapter adapter = new ExchangeAdapter(exchange);
        String requestId = resolveOrCreate(exchange.getRequestHeaders().getFirst(InternalServiceApi.Headers.REQUEST_ID));
        String correlationId = resolveOrCreate(exchange.getRequestHeaders().getFirst(InternalServiceApi.Headers.CORRELATION_ID));
        applyResponsePolicies(exchange, requestId, correlationId);

        String authOutcome = "SKIPPED";
        String userId = "";
        boolean adminRequest = false;

        try {
            if (!isAllowedOrigin(exchange.getRequestHeaders().getFirst("Origin"))) {
                throw new GlobalException(ErrorCode.FORBIDDEN);
            }

            if ("OPTIONS".equalsIgnoreCase(adapter.method())) {
                adapter.sendEmpty(204);
                return;
            }

            InetAddress clientAddress = adapter.remoteAddress().getAddress();
            String clientIp = clientAddress.getHostAddress();

            String path = normalizePath(adapter.uri().getPath());
            if (isHealthPath(path)) {
                adapter.sendJson(200, Jsons.toJson(GlobalResponse.ok(SuccessCode.GET_SUCCESS, Map.of("status", "UP"))));
                return;
            }

            RouteMatch match = routeResolver.resolve(path, adapter.uri().getRawQuery());
            if (match == null) {
                throw new GlobalException(ErrorCode.NOT_FOUND_URL);
            }

            RouteType routeType = match.route().routeType();
            RouteType effectiveRouteType = effectiveRouteType(routeType);
            adminRequest = routeType == RouteType.ADMIN && config.advancedRoutePoliciesEnabled();

            if (routeType == RouteType.INTERNAL) {
                throw new GlobalException(ErrorCode.FORBIDDEN);
            }

            if (!config.ipPolicy().allows(clientIp)) {
                throw new GlobalException(ErrorCode.FORBIDDEN);
            }

            if (isLoginPath(path) && !loginRateLimiter.allow(clientIp)) {
                throw new GlobalException(ErrorCode.TOO_MANY_REQUESTS);
            }

            AuthResult authResult = null;
            if (effectiveRouteType == RouteType.PROTECTED || effectiveRouteType == RouteType.ADMIN) {
                authResult = authenticate(
                        exchange,
                        clientIp,
                        requestId,
                        correlationId,
                        effectiveRouteType == RouteType.ADMIN
                );
                authOutcome = authResult.isAuthenticated() ? "SUCCESS" : "FAILED";
                if (!authResult.isAuthenticated()) {
                    throw new GlobalException(authResult.getStatusCode() == 403 ? ErrorCode.FORBIDDEN : ErrorCode.UNAUTHORIZED);
                }
                userId = authResult.getUserId();
            }

            if (effectiveRouteType == RouteType.ADMIN) {
                if (!config.adminIpPolicy().allows(clientIp)) {
                    throw new GlobalException(ErrorCode.FORBIDDEN);
                }
                if (!authResult.isAdmin()) {
                    throw new GlobalException(ErrorCode.FORBIDDEN);
                }
                if (config.adminPermissionCheckEnabled()
                        && !verifyAdminAccess(adapter.method(), path, requestId, correlationId, authResult)) {
                    throw new GlobalException(ErrorCode.FORBIDDEN);
                }
            }

            enforceBodySize(exchange);

            Map<String, List<String>> proxiedHeaders = sanitizeInboundHeaders(exchange, match.route().upstreamName());
            proxiedHeaders.put(InternalServiceApi.Headers.REQUEST_ID, List.of(requestId));
            proxiedHeaders.put(InternalServiceApi.Headers.CORRELATION_ID, List.of(correlationId));
            if (authResult != null && authResult.isAuthenticated()) {
                authResult.toTrustedHeaders(requestId, correlationId)
                        .forEach((name, values) -> proxiedHeaders.put(name, new ArrayList<>(values)));
            }

            byte[] requestBody = adapter.readBody();
            ProxyRequest proxyRequest = new ProxyRequest(
                    adapter.method(),
                    match.targetUri(),
                    proxiedHeaders,
                    requestBody,
                    clientIp
            );

            ProxyResponse proxyResponse = proxyClient.forward(proxyRequest);
            applyResponsePolicies(exchange, requestId, correlationId);
            adapter.sendStream(proxyResponse.getStatusCode(), proxyResponse.getHeaders(), proxyResponse.getBody());
            logRequest(requestId, correlationId, match.route().upstreamName(), path, adapter.method(), clientIp,
                    proxyResponse.getStatusCode(), authOutcome, userId, adminRequest, startedAt);
        } catch (GlobalException ex) {
            GlobalExceptionHandler.ResponseSpec responseSpec = GlobalExceptionHandler.handleGlobalException(ex);
            adapter.sendJson(responseSpec.httpStatus(), responseSpec.jsonBody());
        } catch (IllegalStateException ex) {
            GlobalExceptionHandler.ResponseSpec responseSpec = GlobalExceptionHandler.fromErrorCode(ErrorCode.PAYLOAD_TOO_LARGE);
            adapter.sendJson(responseSpec.httpStatus(), responseSpec.jsonBody());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            GlobalExceptionHandler.ResponseSpec responseSpec = GlobalExceptionHandler.fromErrorCode(ErrorCode.UPSTREAM_TIMEOUT);
            adapter.sendJson(responseSpec.httpStatus(), responseSpec.jsonBody());
        } catch (IllegalArgumentException ex) {
            GlobalExceptionHandler.ResponseSpec responseSpec = GlobalExceptionHandler.handleIllegalArgumentException(ex);
            adapter.sendJson(responseSpec.httpStatus(), responseSpec.jsonBody());
        } catch (Exception ex) {
            log.log(Level.SEVERE, "requestId=" + requestId + " gateway_error=" + ex.getMessage(), ex);
            GlobalExceptionHandler.ResponseSpec responseSpec = ex instanceof IOException
                    ? GlobalExceptionHandler.fromErrorCode(ErrorCode.UPSTREAM_FAILURE)
                    : GlobalExceptionHandler.handleException(ex);
            adapter.sendJson(responseSpec.httpStatus(), responseSpec.jsonBody());
        } finally {
            adapter.close();
        }
    }

    private AuthResult authenticate(
            HttpExchange exchange,
            String clientIp,
            String requestId,
            String correlationId,
            boolean forceRefresh
    ) throws IOException, InterruptedException {
        String cacheKey = buildAuthCacheKey(exchange, clientIp);
        if (!forceRefresh) {
            AuthResult cached = authValidationCache.get(cacheKey);
            if (cached != null) {
                return cached;
            }
        }

        AuthResult result = authServiceClient.validate(
                config.authValidateUri(),
                exchange.getRequestMethod(),
                exchange.getRequestURI(),
                exchange.getRequestHeaders(),
                clientIp,
                requestId,
                correlationId
        );

        if (!forceRefresh && result.isAuthenticated()) {
            authValidationCache.put(cacheKey, result);
        }
        return result;
    }

    private String buildAuthCacheKey(HttpExchange exchange, String clientIp) {
        String cookie = headerOrEmpty(exchange, "Cookie");
        String ticket = headerOrEmpty(exchange, InternalServiceApi.Headers.SSO_TICKET);
        String authorization = headerOrEmpty(exchange, "Authorization");
        return clientIp + "|" + cookie + "|" + ticket + "|" + authorization;
    }

    private String headerOrEmpty(HttpExchange exchange, String name) {
        String value = exchange.getRequestHeaders().getFirst(name);
        return value == null ? "" : value;
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
        exchange.getResponseHeaders().set(InternalServiceApi.Headers.REQUEST_ID, requestId);
        exchange.getResponseHeaders().set(InternalServiceApi.Headers.CORRELATION_ID, correlationId);
    }

    private boolean isAllowedOrigin(String origin) {
        return origin == null || origin.isBlank() || corsPolicy.isOriginAllowed(origin);
    }

    private boolean isHealthPath(String path) {
        return GatewayApiPaths.HEALTH.equals(path) || GatewayApiPaths.READY.equals(path);
    }

    private boolean isLoginPath(String path) {
        return GatewayApiPaths.AUTH_LOGIN_GITHUB.equals(path);
    }

    private RouteType effectiveRouteType(RouteType routeType) {
        if (!config.advancedRoutePoliciesEnabled() && routeType == RouteType.ADMIN) {
            return RouteType.PROTECTED;
        }
        return routeType;
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

    private Map<String, List<String>> sanitizeInboundHeaders(HttpExchange exchange, String upstreamName) {
        Map<String, List<String>> sanitized = exchange.getRequestHeaders().entrySet().stream()
                .filter(entry -> !TrustedHeaderNames.ALL.contains(entry.getKey().toLowerCase()))
                .collect(java.util.stream.Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> new ArrayList<>(entry.getValue())
                ));

        if (!"auth".equalsIgnoreCase(upstreamName)) {
            sanitized.remove("Cookie");
            sanitized.remove("cookie");
            sanitized.remove("Authorization");
            sanitized.remove("authorization");
            sanitized.remove(InternalServiceApi.Headers.SSO_TICKET);
            sanitized.remove(InternalServiceApi.Headers.SSO_TICKET.toLowerCase());
        }
        return sanitized;
    }

    private boolean verifyAdminAccess(
            String method,
            String path,
            String requestId,
            String correlationId,
            AuthResult authResult
    ) throws IOException, InterruptedException {
        String cacheKey = buildPermissionCacheKey(method, path, authResult);
        Boolean cached = permissionCache.get(cacheKey);
        if (cached != null) {
            return cached;
        }

        boolean allowed = permissionServiceClient.verifyAdminAccess(
                config.adminPermissionVerifyUri(),
                method,
                path,
                requestId,
                correlationId,
                authResult
        );
        permissionCache.put(cacheKey, allowed);
        return allowed;
    }

    private String buildPermissionCacheKey(String method, String path, AuthResult authResult) {
        return authResult.getUserId()
                + "|"
                + authResult.getRole()
                + "|"
                + authResult.getSessionId()
                + "|"
                + method
                + "|"
                + path;
    }

    private void logRequest(
            String requestId,
            String correlationId,
            String upstreamName,
            String path,
            String method,
            String clientIp,
            int status,
            String authOutcome,
            String userId,
            boolean adminRequest,
            long startedAt
    ) {
        long latency = System.currentTimeMillis() - startedAt;
        String line = "requestId=" + requestId
                + " correlationId=" + correlationId
                + " method=" + method
                + " path=" + path
                + " clientIp=" + clientIp
                + " upstream=" + upstreamName
                + " status=" + status
                + " latencyMs=" + latency
                + " auth=" + authOutcome
                + " userId=" + (userId == null ? "" : userId)
                + " admin=" + adminRequest;
        if (adminRequest) {
            log.warning("audit " + line);
            return;
        }
        log.info(line);
    }
}
