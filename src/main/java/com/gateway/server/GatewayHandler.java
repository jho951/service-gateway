package com.gateway.server;

import com.gateway.auth.AuthResult;
import com.gateway.auth.AuthServiceClient;
import com.gateway.api.GatewayApiPaths;
import com.gateway.api.InternalServiceApi;
import com.gateway.code.ErrorCode;
import com.gateway.code.SuccessCode;
import com.gateway.config.GatewayConfig;
import com.gateway.exception.GlobalException;
import com.gateway.exception.GlobalExceptionHandler;
import com.gateway.http.ExchangeAdapter;
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
import com.gateway.security.JwtPrecheckPolicy;
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
    private final ReverseProxyClient proxyClient;
    private final CorsPolicy corsPolicy;
    private final SecurityHeadersPolicy securityHeadersPolicy;
    private final RequestWindowRateLimiter loginRateLimiter;
    private final JwtPrecheckPolicy jwtPrecheckPolicy;
    private final AuthServiceClient authServiceClient;

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
        this.authServiceClient = new AuthServiceClient(config.requestTimeout());
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        long startedAt = System.currentTimeMillis();
        ExchangeAdapter adapter = new ExchangeAdapter(exchange);
        String requestId = resolveOrCreate(exchange.getRequestHeaders().getFirst(InternalServiceApi.Headers.REQUEST_ID));
        String correlationId = resolveOrCreate(exchange.getRequestHeaders().getFirst(InternalServiceApi.Headers.CORRELATION_ID));
        applyResponsePolicies(exchange, requestId, correlationId);

        String authOutcome = "FORWARDED";
        String resolvedUserId = "";

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
                GlobalExceptionHandler.ResponseSpec responseSpec =
                        GlobalExceptionHandler.fromSuccessCode(SuccessCode.GET_SUCCESS, Map.of("status", "UP"));
                adapter.sendJson(responseSpec.httpStatus(), responseSpec.jsonBody());
                return;
            }

            RouteMatch match = routeResolver.resolve(path, adapter.uri().getRawQuery());
            if (match == null) {
                throw new GlobalException(ErrorCode.NOT_FOUND_URL);
            }

            RouteType routeType = match.route().routeType();
            if (routeType == RouteType.INTERNAL && !config.internalIpPolicy().allows(clientIp)) {
                throw new GlobalException(ErrorCode.FORBIDDEN);
            }

            if (shouldApplyGatewayIpGuard(routeType) && !config.ipPolicy().allows(clientIp)) {
                throw new GlobalException(ErrorCode.FORBIDDEN);
            }

            if (isLoginPath(path) && !loginRateLimiter.allow(clientIp)) {
                throw new GlobalException(ErrorCode.TOO_MANY_REQUESTS);
            }

            if (requiresAuthorizationPrecheck(match.route(), path)) {
                String authorizationHeader = exchange.getRequestHeaders().getFirst("Authorization");
                JwtPrecheckPolicy.Result precheckResult =
                        jwtPrecheckPolicy.precheck(authorizationHeader);
                authOutcome = precheckResult.outcome();
                if (!precheckResult.accepted()) {
                    throw new GlobalException(ErrorCode.UNAUTHORIZED);
                }
            }

            if (requiresGatewayManagedAuth(match.route(), path)) {
                String authorizationHeader = exchange.getRequestHeaders().getFirst("Authorization");
                AuthResult authResult = authServiceClient.validateSession(
                        config.authServiceUri(),
                        authorizationHeader,
                        requestId,
                        correlationId
                );
                if (!authResult.isAuthenticated()) {
                    throw new GlobalException(ErrorCode.UNAUTHORIZED);
                }
                resolvedUserId = authResult.getUserId();
                authOutcome = "AUTH_SERVICE_VALIDATED";
            }

            enforceBodySize(exchange);

            Map<String, List<String>> proxiedHeaders = sanitizeInboundHeaders(exchange, match.route());
            proxiedHeaders.put(InternalServiceApi.Headers.REQUEST_ID, List.of(requestId));
            proxiedHeaders.put(InternalServiceApi.Headers.CORRELATION_ID, List.of(correlationId));
            injectTrustedContext(proxiedHeaders, resolvedUserId);

            byte[] requestBody = adapter.readBody();
            ProxyRequest proxyRequest = new ProxyRequest(
                    adapter.method(),
                    match.targetUri(),
                    proxiedHeaders,
                    requestBody,
                    clientIp
            );

            ProxyResponse proxyResponse = proxyClient.forward(proxyRequest);
            if ("FORWARDED".equals(authOutcome)) {
                authOutcome = "PRECHECK_BYPASSED";
            }
            applyResponsePolicies(exchange, requestId, correlationId);
            adapter.sendStream(proxyResponse.getStatusCode(), proxyResponse.getHeaders(), proxyResponse.getBody());
            logRequest(requestId, correlationId, match.route().upstreamName(), path, adapter.method(), clientIp,
                    proxyResponse.getStatusCode(), authOutcome, resolvedUserId, false, startedAt);
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
        } catch (IOException ex) {
            log.log(Level.WARNING, "requestId=" + requestId + " upstream_failure=" + ex.getMessage());
            GlobalExceptionHandler.ResponseSpec responseSpec = GlobalExceptionHandler.fromErrorCode(ErrorCode.UPSTREAM_FAILURE);
            adapter.sendJson(responseSpec.httpStatus(), responseSpec.jsonBody());
        } catch (IllegalArgumentException ex) {
            GlobalExceptionHandler.ResponseSpec responseSpec = GlobalExceptionHandler.handleIllegalArgumentException(ex);
            adapter.sendJson(responseSpec.httpStatus(), responseSpec.jsonBody());
        } catch (Exception ex) {
            log.log(Level.SEVERE, "requestId=" + requestId + " gateway_error=" + ex.getMessage(), ex);
            GlobalExceptionHandler.ResponseSpec responseSpec = GlobalExceptionHandler.handleException(ex);
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
        return GatewayApiPaths.AUTH_LOGIN.equals(path)
                || GatewayApiPaths.AUTH_LOGIN_GITHUB.equals(path)
                || GatewayApiPaths.AUTH_SSO_START.equals(path)
                || path.startsWith("/auth/oauth2/authorize/")
                || path.startsWith("/oauth2/authorization/");
    }

    private boolean shouldApplyGatewayIpGuard(RouteType routeType) {
        return routeType == RouteType.ADMIN;
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
        return requiresGatewayManagedAuth(route, path)
                || GatewayApiPaths.USERS_ME.equals(path)
                || GatewayApiPaths.INTERNAL_USERS_ALL.substring(0, GatewayApiPaths.INTERNAL_USERS_ALL.length() - 3).equals(path)
                || path.startsWith("/internal/users/");
    }

    private boolean requiresGatewayManagedAuth(com.gateway.routing.RouteDefinition route, String path) {
        if (route.routeType() == RouteType.PROTECTED && "block".equals(route.upstreamName())) {
            return true;
        }
        if (GatewayApiPaths.USERS_ME.equals(path)) {
            return true;
        }
        return GatewayApiPaths.INTERNAL_USERS_ALL.substring(0, GatewayApiPaths.INTERNAL_USERS_ALL.length() - 3).equals(path)
                || path.startsWith("/internal/users/");
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
