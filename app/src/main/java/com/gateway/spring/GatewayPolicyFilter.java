package com.gateway.spring;

import com.gateway.audit.GatewayOperationalAuditPort;
import com.gateway.auth.AuthResult;
import com.gateway.code.GatewayErrorCode;
import com.gateway.config.GatewayConfig;
import com.gateway.contract.internal.header.ServiceHeaders;
import com.gateway.contract.internal.header.TraceHeaders;
import com.gateway.exception.GatewayException;
import com.gateway.exception.ResponseSpec;
import com.gateway.http.Jsons;
import com.gateway.http.TrustedHeaderNames;
import com.gateway.metrics.GatewayMetrics;
import com.gateway.policy.CorsPolicy;
import com.gateway.routing.RouteDefinition;
import com.gateway.routing.RouteMatch;
import com.gateway.routing.RouteResolver;
import com.gateway.routing.RouteType;
import com.gateway.security.InternalJwtIssuer;
import com.gateway.security.RequestChannel;
import io.netty.channel.ConnectTimeoutException;
import io.netty.handler.timeout.ReadTimeoutException;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeoutException;
import java.util.logging.Logger;

@Component
public final class GatewayPolicyFilter implements GlobalFilter, Ordered {
    private static final Logger log = Logger.getLogger(GatewayPolicyFilter.class.getName());

    private final GatewayConfig config;
    private final GatewayMetrics metrics;
    private final RouteResolver routeResolver;
    private final CorsPolicy corsPolicy;
    private final InternalJwtIssuer internalJwtIssuer;
    private final GatewayOperationalAuditPort gatewayOperationalAuditPort;
    private final GatewayFailureResponseFactory failureResponseFactory;
    private final GatewayResponseContractWriter responseContractWriter;

    public GatewayPolicyFilter(
            GatewayConfig config,
            GatewayMetrics metrics,
            RouteResolver gatewayRouteResolver,
            GatewayOperationalAuditPort gatewayOperationalAuditPort,
            GatewayFailureResponseFactory failureResponseFactory,
            GatewayResponseContractWriter responseContractWriter
    ) {
        this.config = config;
        this.metrics = metrics;
        this.routeResolver = gatewayRouteResolver;
        this.corsPolicy = new CorsPolicy(config.allowedOrigins());
        this.internalJwtIssuer = new InternalJwtIssuer(
                config.internalJwtSharedSecret(),
                config.internalJwtIssuer(),
                config.internalJwtAudience(),
                config.internalJwtTtlSeconds()
        );
        this.gatewayOperationalAuditPort = gatewayOperationalAuditPort;
        this.failureResponseFactory = failureResponseFactory;
        this.responseContractWriter = responseContractWriter;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        long startedAt = System.currentTimeMillis();
        metrics.incrementInFlight();

        ServerHttpRequest request = exchange.getRequest();
        String requestPath = normalizePath(request.getPath().pathWithinApplication().value());
        String requestMethod = request.getMethod().name();
        String requestId = resolveOrCreate(request.getHeaders().getFirst(TraceHeaders.REQUEST_ID));
        String correlationId = resolveOrCreate(request.getHeaders().getFirst(TraceHeaders.CORRELATION_ID));
        String clientIp = resolveClientIp(request);
        RouteMatch match = resolveRouteMatch(exchange, requestPath);

        applyResponseHeaders(exchange, requestId, correlationId);
        if (match != null) {
            rewriteLocationBeforeCommit(exchange, match.route());
        }
        if ("OPTIONS".equalsIgnoreCase(requestMethod)) {
            exchange.getResponse().setStatusCode(HttpStatus.NO_CONTENT);
            record(exchange, FilterContext.failed(requestMethod, requestPath, clientIp, match, "CORS_PREFLIGHT"), startedAt, "");
            return exchange.getResponse().setComplete();
        }

        try {
            FilterContext context = prepare(exchange, match, requestPath, requestId, correlationId);
            if (shouldServeLocalAuthResponse(requestPath, context.authResult())) {
                return write(exchange, localAuthResponse(requestPath, context.authResult()))
                        .doOnSuccess(ignored -> record(exchange, context, startedAt, null));
            }
            return chain.filter(context.exchange())
                    .doOnSuccess(ignored -> record(context.exchange(), context, startedAt, null))
                    .onErrorResume(GatewayException.class, ex -> {
                        record(exchange, FilterContext.failed(requestMethod, requestPath, clientIp, match, ex.getErrorCode().name()), startedAt, ex.getErrorCode().name());
                        return write(exchange, failureResponseFactory.fromThrowable(ex, requestPath, requestId));
                    })
                    .onErrorResume(IllegalArgumentException.class, ex -> {
                        record(exchange, FilterContext.failed(requestMethod, requestPath, clientIp, match, "INVALID_REQUEST"), startedAt, "INVALID_REQUEST");
                        return write(exchange, failureResponseFactory.fromThrowable(ex, requestPath, requestId));
                    })
                    .onErrorResume(Exception.class, ex -> {
                        GatewayErrorCode errorCode = resolveUnhandledErrorCode(ex);
                        record(exchange, FilterContext.failed(requestMethod, requestPath, clientIp, match, errorCode.name()), startedAt, errorCode.name());
                        return write(exchange, failureResponseFactory.fromThrowable(ex, requestPath, requestId));
                    });
        } catch (GatewayException ex) {
            record(exchange, FilterContext.failed(requestMethod, requestPath, clientIp, match, ex.getErrorCode().name()), startedAt, ex.getErrorCode().name());
            return write(exchange, failureResponseFactory.fromThrowable(ex, requestPath, requestId));
        } catch (IllegalArgumentException ex) {
            record(exchange, FilterContext.failed(requestMethod, requestPath, clientIp, match, "INVALID_REQUEST"), startedAt, "INVALID_REQUEST");
            return write(exchange, failureResponseFactory.fromThrowable(ex, requestPath, requestId));
        } catch (Exception ex) {
            GatewayErrorCode errorCode = resolveUnhandledErrorCode(ex);
            record(exchange, FilterContext.failed(requestMethod, requestPath, clientIp, match, errorCode.name()), startedAt, errorCode.name());
            return write(exchange, failureResponseFactory.fromThrowable(ex, requestPath, requestId));
        }
    }

    private FilterContext prepare(
            ServerWebExchange exchange,
            RouteMatch match,
            String requestPath,
            String requestId,
            String correlationId
    ) {
        if (match == null) {
            throw new GatewayException(GatewayErrorCode.NOT_FOUND);
        }

        RouteDefinition route = match.route();
        String origin = exchange.getRequest().getHeaders().getFirst("Origin");
        if (!isAllowedOrigin(origin)) {
            throw new GatewayException(GatewayErrorCode.FORBIDDEN);
        }
        if (contentLengthTooLarge(exchange)) {
            throw new GatewayException(GatewayErrorCode.PAYLOAD_TOO_LARGE);
        }

        AuthResult authResult = exchange.getAttribute(GatewaySecurityExchangeAttributes.AUTH_RESULT);
        RequestChannel requestChannel = exchange.getAttribute(GatewaySecurityExchangeAttributes.REQUEST_CHANNEL);
        String authOutcome = exchange.getAttributeOrDefault(
                GatewaySecurityExchangeAttributes.AUTH_OUTCOME,
                "PRECHECK_BYPASSED"
        );

        if ((route.routeType() == RouteType.PROTECTED || route.routeType() == RouteType.ADMIN)
                && (authResult == null || authResult.getUserId() == null || authResult.getUserId().isBlank())) {
            throw new GatewayException(GatewayErrorCode.UNAUTHORIZED);
        }

        String resolvedUserId = authResult == null ? "" : authResult.getUserId();
        String resolvedUserStatus = authResult == null ? "" : authResult.getStatus();
        String upstreamAuthorizationHeader = resolvedUserId.isBlank()
                ? null
                : internalJwtIssuer.issueForUser(resolvedUserId, resolvedUserStatus);

        ServerWebExchange mutated = mutateExchange(
                exchange,
                route,
                requestPath,
                requestId,
                correlationId,
                resolvedUserId,
                upstreamAuthorizationHeader,
                requestChannel
        );
        return new FilterContext(
                mutated,
                exchange.getRequest().getMethod().name(),
                requestPath,
                resolveClientIp(exchange.getRequest()),
                route.upstreamName(),
                authOutcome,
                resolvedUserId,
                authResult
        );
    }

    private ServerWebExchange mutateExchange(
            ServerWebExchange exchange,
            RouteDefinition route,
            String requestPath,
            String requestId,
            String correlationId,
            String resolvedUserId,
            String upstreamAuthorizationHeader,
            RequestChannel requestChannel
    ) {
        @SuppressWarnings("unchecked")
        Map<String, String> downstreamHeaders = (Map<String, String>) exchange.getAttribute(
                "security.downstream.headers"
        );

        String upstreamPath = route.rewritePath(requestPath);
        ServerHttpRequest.Builder builder = exchange.getRequest().mutate();
        builder.path(upstreamPath);
        builder.headers(headers -> {
            removeTrustedHeaders(headers);
            headers.remove("X-Forwarded-Prefix");
            if (!shouldForwardAuthorizationHeader(route)) {
                headers.remove(HttpHeaders.AUTHORIZATION);
            }
            headers.set(TraceHeaders.REQUEST_ID, requestId);
            headers.set(TraceHeaders.CORRELATION_ID, correlationId);
            if (downstreamHeaders != null) {
                downstreamHeaders.forEach(headers::set);
            }
            if (resolvedUserId != null && !resolvedUserId.isBlank()) {
                headers.set(ServiceHeaders.Trusted.USER_ID, resolvedUserId);
                if (requestChannel != null) {
                    headers.set(ServiceHeaders.Trusted.CLIENT_TYPE, requestChannel.headerValue());
                    log.info("trusted_context_injected requestId=" + requestId
                            + " path=" + requestPath
                            + " upstream=" + route.upstreamName()
                            + " channel=" + requestChannel.headerValue()
                            + " userId=" + resolvedUserId);
                }
            }
            if (shouldForwardAuthorizationHeader(route)
                    && upstreamAuthorizationHeader != null
                    && !upstreamAuthorizationHeader.isBlank()) {
                headers.set(HttpHeaders.AUTHORIZATION, upstreamAuthorizationHeader);
            }
        });
        return exchange.mutate().request(builder.build()).build();
    }

    private RouteMatch resolveRouteMatch(ServerWebExchange exchange, String requestPath) {
        RouteMatch match = exchange.getAttribute(GatewaySecurityExchangeAttributes.ROUTE_MATCH);
        if (match != null) {
            return match;
        }
        return routeResolver.resolve(requestPath, exchange.getRequest().getURI().getRawQuery());
    }

    private void applyResponseHeaders(ServerWebExchange exchange, String requestId, String correlationId) {
        HttpHeaders headers = exchange.getResponse().getHeaders();
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Frame-Options", "DENY");
        headers.set("Referrer-Policy", "no-referrer");
        headers.set("Cache-Control", "no-store");
        headers.set(TraceHeaders.REQUEST_ID, requestId);
        headers.set(TraceHeaders.CORRELATION_ID, correlationId);

        String origin = exchange.getRequest().getHeaders().getFirst("Origin");
        String allowOrigin = resolveAllowOrigin(origin);
        if (allowOrigin != null) {
            headers.setAccessControlAllowOrigin(allowOrigin);
            headers.set("Vary", "Origin");
            headers.setAccessControlAllowCredentials(true);
            headers.setAccessControlAllowHeaders(List.of("Authorization", "Content-Type", "X-Request-Id"));
            headers.setAccessControlAllowMethods(List.of(
                    org.springframework.http.HttpMethod.GET,
                    org.springframework.http.HttpMethod.POST,
                    org.springframework.http.HttpMethod.PUT,
                    org.springframework.http.HttpMethod.PATCH,
                    org.springframework.http.HttpMethod.DELETE,
                    org.springframework.http.HttpMethod.OPTIONS
            ));
            headers.setAccessControlMaxAge(600);
        }
    }

    private void rewriteLocationBeforeCommit(ServerWebExchange exchange, RouteDefinition route) {
        exchange.getResponse().beforeCommit(() -> {
            List<String> locations = exchange.getResponse().getHeaders().get(HttpHeaders.LOCATION);
            if (locations != null && !locations.isEmpty()) {
                exchange.getResponse().getHeaders().put(
                        HttpHeaders.LOCATION,
                        locations.stream().map(location -> rewriteLocation(route, location)).toList()
                );
            }
            return Mono.empty();
        });
    }

    private Mono<Void> write(ServerWebExchange exchange, ResponseSpec responseSpec) {
        return responseContractWriter.write(exchange, responseSpec);
    }

    private boolean shouldServeLocalAuthResponse(String requestPath, AuthResult authResult) {
        if (authResult == null || !authResult.isAuthenticated()) {
            return false;
        }
        return "/v1/auth/me".equals(requestPath) || "/v1/auth/session".equals(requestPath);
    }

    private ResponseSpec localAuthResponse(String requestPath, AuthResult authResult) {
        if ("/v1/auth/session".equals(requestPath)) {
            return new ResponseSpec(200, Jsons.toJson(Map.of(
                    "authenticated", true,
                    "userId", safe(authResult.getUserId()),
                    "role", safe(authResult.getRole()),
                    "status", safe(authResult.getStatus()),
                    "sessionId", safe(authResult.getSessionId())
            )));
        }

        return new ResponseSpec(200, Jsons.toJson(Map.of(
                "id", safe(authResult.getUserId()),
                "email", safe(authResult.getEmail()),
                "name", safe(authResult.getName()),
                "avatarUrl", safe(authResult.getAvatarUrl()),
                "role", safe(authResult.getRole()),
                "status", safe(authResult.getStatus())
        )));
    }

    private void record(ServerWebExchange exchange, FilterContext context, long startedAt, String failureReason) {
        try {
            int status = 500;
            if (exchange.getResponse().getStatusCode() != null) {
                status = exchange.getResponse().getStatusCode().value();
            }
            metrics.recordRequest(context.method(), context.upstream(), status, context.authOutcome(), elapsedMillis(startedAt));
            gatewayOperationalAuditPort.logRequest(
                    context.method(),
                    context.path(),
                    exchange.getResponse().getHeaders().getFirst(TraceHeaders.REQUEST_ID),
                    context.clientIp(),
                    context.userId(),
                    context.upstream(),
                    status,
                    context.authOutcome(),
                    failureReason == null ? "" : failureReason
            );
        } finally {
            metrics.decrementInFlight();
        }
    }

    private boolean shouldForwardAuthorizationHeader(RouteDefinition route) {
        if (route.routeType() == RouteType.PROTECTED || route.routeType() == RouteType.ADMIN) {
            return false;
        }
        return config.forwardAuthorizationHeader()
                || (route.routeType() == RouteType.PUBLIC && "auth".equals(route.upstreamName()));
    }

    private boolean contentLengthTooLarge(ServerWebExchange exchange) {
        long length = exchange.getRequest().getHeaders().getContentLength();
        return length > config.maxBodyBytes();
    }

    private boolean isAllowedOrigin(String origin) {
        return origin == null || origin.isBlank() || corsPolicy.isOriginAllowed(origin);
    }

    private String resolveAllowOrigin(String origin) {
        if (origin == null || origin.isBlank()) {
            return null;
        }
        return corsPolicy.isOriginAllowed(origin) ? origin : null;
    }

    private void removeTrustedHeaders(HttpHeaders headers) {
        for (String key : new ArrayList<>(headers.keySet())) {
            if (TrustedHeaderNames.isTrusted(key)) {
                headers.remove(key);
            }
        }
    }

    private String rewriteLocation(RouteDefinition route, String location) {
        if (location == null || location.isBlank()) {
            return location;
        }
        if (route.stripPrefix() == null || route.stripPrefix().isBlank()) {
            return location;
        }
        if (location.startsWith(route.stripPrefix() + "/")) {
            return location;
        }
        if (location.startsWith("/oauth2/") || location.startsWith("/login/oauth2/") || location.startsWith("/.well-known/")) {
            return route.stripPrefix() + location;
        }
        return location;
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

    private String resolveClientIp(ServerHttpRequest request) {
        InetSocketAddress remoteAddress = request.getRemoteAddress();
        if (remoteAddress == null || remoteAddress.getAddress() == null) {
            return "";
        }
        return remoteAddress.getAddress().getHostAddress();
    }

    private long elapsedMillis(long startedAt) {
        return Math.max(System.currentTimeMillis() - startedAt, 0);
    }

    private GatewayErrorCode resolveUnhandledErrorCode(Throwable error) {
        if (hasCause(error, ReadTimeoutException.class) || hasCause(error, TimeoutException.class)) {
            return GatewayErrorCode.UPSTREAM_TIMEOUT;
        }
        if (hasCause(error, ConnectException.class)
                || hasCause(error, ConnectTimeoutException.class)
                || hasCause(error, UnknownHostException.class)) {
            return GatewayErrorCode.UPSTREAM_FAILURE;
        }
        return GatewayErrorCode.INTERNAL_ERROR;
    }

    private boolean hasCause(Throwable error, Class<? extends Throwable> type) {
        Throwable current = error;
        while (current != null) {
            if (type.isInstance(current)) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }

    private record FilterContext(
            ServerWebExchange exchange,
            String method,
            String path,
            String clientIp,
            String upstream,
            String authOutcome,
            String userId,
            AuthResult authResult
    ) {
        private static FilterContext failed(String method, String path, String clientIp, RouteMatch match, String authOutcome) {
            String upstream = match == null ? "gateway" : match.route().upstreamName();
            return new FilterContext(null, method, path, clientIp, upstream, authOutcome, "", null);
        }
    }
}
