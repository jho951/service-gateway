package com.gateway.spring;

import com.gateway.auth.AuthResult;
import com.gateway.code.GatewayErrorCode;
import com.gateway.config.GatewayConfig;
import com.gateway.contract.external.header.ExternalApiHeaders;
import com.gateway.contract.external.path.AuthApiPaths;
import com.gateway.contract.internal.header.ServiceHeaders;
import com.gateway.contract.internal.header.TraceHeaders;
import com.gateway.exception.GatewayException;
import com.gateway.metrics.GatewayMetrics;
import com.gateway.routing.RouteMatch;
import com.gateway.routing.RouteResolver;
import com.gateway.routing.RouteType;
import com.gateway.security.AuthSessionValidator;
import com.gateway.security.AuthVerificationResult;
import com.gateway.security.RequestChannel;
import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.api.SecurityRequest;
import io.github.jho951.platform.security.policy.AuthMode;
import io.github.jho951.platform.security.policy.ClientType;
import io.github.jho951.platform.security.policy.SecurityBoundaryType;
import io.github.jho951.platform.security.web.ReactiveSecurityFailureResponseWriter;
import io.github.jho951.platform.security.web.SecurityDownstreamIdentityPropagator;
import io.github.jho951.platform.security.web.SecurityFailureResponse;
import io.github.jho951.platform.security.web.SecurityIngressAdapter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Component
public final class GatewayPlatformSecurityWebFilter implements WebFilter, Ordered {
    private final RouteResolver routeResolver;
    private final AuthSessionValidator authSessionValidator;
    private final SecurityIngressAdapter securityIngressAdapter;
    private final GatewaySecurityAuditPort gatewaySecurityAuditPort;
    private final ReactiveSecurityFailureResponseWriter failureResponseWriter;
    private final SecurityDownstreamIdentityPropagator downstreamIdentityPropagator;
    private final GatewayMetrics metrics;
    private final GatewayConfig config;

    public GatewayPlatformSecurityWebFilter(
            RouteResolver routeResolver,
            AuthSessionValidator gatewayAuthSessionValidator,
            SecurityIngressAdapter gatewaySecurityIngressAdapter,
            GatewaySecurityAuditPort gatewaySecurityAuditPort,
            ReactiveSecurityFailureResponseWriter gatewaySecurityFailureResponseWriter,
            GatewayMetrics metrics,
            GatewayConfig config
    ) {
        this.routeResolver = routeResolver;
        this.authSessionValidator = gatewayAuthSessionValidator;
        this.securityIngressAdapter = gatewaySecurityIngressAdapter;
        this.gatewaySecurityAuditPort = gatewaySecurityAuditPort;
        this.failureResponseWriter = gatewaySecurityFailureResponseWriter;
        this.downstreamIdentityPropagator = new SecurityDownstreamIdentityPropagator();
        this.metrics = metrics;
        this.config = config;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String requestPath = normalizePath(exchange.getRequest().getPath().pathWithinApplication().value());
        String requestMethod = exchange.getRequest().getMethod() == null
                ? "GET"
                : exchange.getRequest().getMethod().name();
        RouteMatch match = routeResolver.resolve(requestPath, exchange.getRequest().getURI().getRawQuery());
        if (match != null) {
            exchange.getAttributes().put(GatewaySecurityExchangeAttributes.ROUTE_MATCH, match);
        }

        if ("OPTIONS".equalsIgnoreCase(requestMethod) || match == null) {
            return chain.filter(exchange);
        }

        long startedAt = System.currentTimeMillis();
        String requestId = resolveRequestId(exchange);
        String correlationId = resolveCorrelationId(exchange);
        String clientIp = resolveClientIp(exchange);

        return Mono.fromCallable(() -> evaluate(exchange, match, requestMethod, requestPath, requestId, correlationId, clientIp))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(decision -> {
                    if (!decision.allowed()) {
                        return failureResponseWriter.write(exchange, decision.failureResponse())
                                .doOnSuccess(ignored -> recordDenied(exchange, decision, startedAt, clientIp));
                    }
                    exchange.getAttributes().put(
                            SecurityDownstreamIdentityPropagator.ATTR_DOWNSTREAM_HEADERS,
                            downstreamIdentityPropagator.asAttributes(decision.evaluationResult())
                    );
                    exchange.getAttributes().put(GatewaySecurityExchangeAttributes.AUTH_OUTCOME, decision.authOutcome());
                    if (decision.requestChannel() != null) {
                        exchange.getAttributes().put(GatewaySecurityExchangeAttributes.REQUEST_CHANNEL, decision.requestChannel());
                    }
                    if (decision.authResult() != null) {
                        exchange.getAttributes().put(GatewaySecurityExchangeAttributes.AUTH_RESULT, decision.authResult());
                    }
                    exchange.getAttributes().put(GatewaySecurityExchangeAttributes.SECURITY_EVALUATION_RESULT, decision.evaluationResult());
                    return chain.filter(exchange);
                })
                .onErrorResume(GatewayException.class, ex -> writeGatewayFailure(
                        exchange,
                        match,
                        requestMethod,
                        requestPath,
                        clientIp,
                        startedAt,
                        ex.getErrorCode()
                ));
    }

    private SecurityDecision evaluate(
            ServerWebExchange exchange,
            RouteMatch match,
            String requestMethod,
            String requestPath,
            String requestId,
            String correlationId,
            String clientIp
    ) throws IOException, InterruptedException {
        RouteType routeType = match.route().routeType();
        RequestChannel requestChannel = resolveRequestChannel(exchange, requestPath, routeType);
        AuthAttempt authAttempt = authenticate(exchange, routeType, requestChannel, requestId, correlationId);

        if (authAttempt.failureCode() != null) {
            exchange.getAttributes().put(GatewaySecurityExchangeAttributes.FAILURE_ERROR_CODE, authAttempt.failureCode());
        } else {
            exchange.getAttributes().remove(GatewaySecurityExchangeAttributes.FAILURE_ERROR_CODE);
        }

        SecurityContext securityContext = buildSecurityContext(routeType, authAttempt);
        SecurityRequest securityRequest = securityIngressAdapter.withResolvedBoundary(
                buildSecurityRequest(
                        routeType,
                        requestMethod,
                        requestPath,
                        requestId,
                        correlationId,
                        clientIp,
                        requestChannel,
                        authAttempt,
                        securityContext
                )
        );
        SecurityEvaluationResult evaluationResult = securityIngressAdapter.evaluateResult(securityRequest, securityContext);
        gatewaySecurityAuditPort.publish(evaluationResult);
        SecurityFailureResponse failureResponse = SecurityFailureResponse.from(evaluationResult.verdict());

        if (failureResponse.status() != 200) {
            return SecurityDecision.denied(
                    match,
                    requestMethod,
                    requestPath,
                    authAttempt.authOutcome(),
                    authAttempt.authResult(),
                    requestChannel,
                    evaluationResult,
                    failureResponse,
                    authAttempt.failureCode()
            );
        }

        exchange.getAttributes().remove(GatewaySecurityExchangeAttributes.FAILURE_ERROR_CODE);
        return SecurityDecision.allowed(
                match,
                requestMethod,
                requestPath,
                authAttempt.authOutcome(),
                authAttempt.authResult(),
                requestChannel,
                evaluationResult
        );
    }

    private AuthAttempt authenticate(
            ServerWebExchange exchange,
            RouteType routeType,
            RequestChannel requestChannel,
            String requestId,
            String correlationId
    ) throws IOException, InterruptedException {
        if (routeType == RouteType.INTERNAL) {
            String provided = exchange.getRequest().getHeaders().getFirst(ServiceHeaders.Auth.INTERNAL_REQUEST_SECRET);
            String expected = config.internalRequestSecret();
            boolean verified = expected != null && !expected.isBlank() && expected.equals(provided);
            return verified
                    ? AuthAttempt.internal()
                    : AuthAttempt.failed("INTERNAL_SECRET_MISSING", AuthMode.HYBRID, GatewayErrorCode.FORBIDDEN);
        }
        if (routeType == RouteType.PUBLIC) {
            return AuthAttempt.anonymous("PRECHECK_BYPASSED");
        }
        return authenticateProtectedRequest(exchange, requestChannel, requestId, correlationId);
    }

    private AuthAttempt authenticateProtectedRequest(
            ServerWebExchange exchange,
            RequestChannel requestChannel,
            String requestId,
            String correlationId
    ) throws IOException, InterruptedException {
        String authForVerification = resolveIncomingAuth(requestChannel, exchange, requestId, correlationId);
        if (authForVerification == null || authForVerification.isBlank()) {
            return handleMissingCredentials(exchange, requestChannel);
        }

        AuthVerificationResult verificationResult = authSessionValidator.verifyBearer(authForVerification, requestId, correlationId);
        AuthResult authResult = verificationResult.authResult();
        if (!verificationResult.verified() || authResult == null || !hasUserId(authResult)) {
            return AuthAttempt.failed(
                    verificationResult.outcome(),
                    resolvePlatformAuthMode(requestChannel, true),
                    GatewayErrorCode.UNAUTHORIZED
            );
        }
        return AuthAttempt.authenticated(
                authResult,
                verificationResult.outcome(),
                resolvePlatformAuthMode(requestChannel, true)
        );
    }

    private AuthAttempt handleMissingCredentials(ServerWebExchange exchange, RequestChannel requestChannel) throws IOException, InterruptedException {
        if (requestChannel != null && requestChannel.isWeb()) {
            String cookieHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.COOKIE);
            if (cookieHeader == null || cookieHeader.isBlank() || !cookieHeader.contains("sso_session=")) {
                String authorizationHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
                if (hasBearerToken(authorizationHeader) || hasBasicToken(authorizationHeader)) {
                    return AuthAttempt.failed("AUTH_CHANNEL_MISMATCH", AuthMode.SESSION, GatewayErrorCode.AUTH_CHANNEL_MISMATCH);
                }
                return AuthAttempt.failed("MISSING_AUTH_CREDENTIALS", AuthMode.SESSION, GatewayErrorCode.MISSING_AUTH_CREDENTIALS);
            }
            AuthVerificationResult sessionVerificationResult = authSessionValidator.verifyCookie(
                    cookieHeader,
                    resolveRequestId(exchange),
                    resolveCorrelationId(exchange)
            );
            AuthResult sessionAuthResult = sessionVerificationResult.authResult();
            if (!sessionVerificationResult.verified() || sessionAuthResult == null || !hasUserId(sessionAuthResult)) {
                return AuthAttempt.failed(
                        sessionVerificationResult.outcome(),
                        AuthMode.SESSION,
                        GatewayErrorCode.UNAUTHORIZED
                );
            }
            return AuthAttempt.authenticated(
                    sessionAuthResult,
                    sessionVerificationResult.outcome(),
                    resolvePlatformAuthMode(requestChannel, false)
            );
        }

        if (hasCookieBasedAuth(exchange.getRequest().getHeaders().getFirst(HttpHeaders.COOKIE))) {
            return AuthAttempt.failed(
                    "AUTH_CHANNEL_MISMATCH",
                    resolvePlatformAuthMode(requestChannel, false),
                    GatewayErrorCode.AUTH_CHANNEL_MISMATCH
            );
        }
        return AuthAttempt.failed(
                "MISSING_AUTH_CREDENTIALS",
                resolvePlatformAuthMode(requestChannel, false),
                GatewayErrorCode.MISSING_AUTH_CREDENTIALS
        );
    }

    private SecurityRequest buildSecurityRequest(
            RouteType routeType,
            String requestMethod,
            String requestPath,
            String requestId,
            String correlationId,
            String clientIp,
            RequestChannel requestChannel,
            AuthAttempt authAttempt,
            SecurityContext securityContext
    ) {
        LinkedHashMap<String, String> attributes = new LinkedHashMap<>();
        SecurityBoundaryType boundaryType = mapBoundary(routeType);
        AuthMode authMode = authAttempt.authMode();
        ClientType clientType = mapClientType(routeType, requestChannel);

        attributes.put(GatewayPlatformSecurityConfiguration.ATTR_BOUNDARY, boundaryType.name());
        attributes.put(GatewayPlatformSecurityConfiguration.ATTR_CLIENT_TYPE, clientType.name());
        attributes.put(GatewayPlatformSecurityConfiguration.ATTR_AUTH_MODE, authMode.name());
        attributes.put(GatewayPlatformSecurityConfiguration.ATTR_REQUEST_ID, requestId);
        attributes.put(GatewayPlatformSecurityConfiguration.ATTR_CORRELATION_ID, correlationId);
        attributes.put(GatewayPlatformSecurityConfiguration.ATTR_ORIGINAL_METHOD, requestMethod);
        attributes.put(GatewayPlatformSecurityConfiguration.ATTR_ORIGINAL_PATH, requestPath);
        attributes.put("security.boundary", boundaryType.name());
        attributes.put("security.auth.mode", authMode.name());

        if (authAttempt.authResult() != null) {
            AuthResult authResult = authAttempt.authResult();
            if (authResult.getSessionId() != null && !authResult.getSessionId().isBlank()) {
                attributes.put("auth.sessionId", authResult.getSessionId());
            }
            if (authResult.getStatus() != null && !authResult.getStatus().isBlank()) {
                attributes.put(GatewayPlatformSecurityConfiguration.ATTR_USER_STATUS, authResult.getStatus());
            }
        }
        String authorizationHeader = exchangeAuthorizationValue(authAttempt, requestChannel);
        if (authorizationHeader != null) {
            attributes.put("auth.accessToken", authorizationHeader);
        }
        if (routeType == RouteType.INTERNAL && authAttempt.authenticated()) {
            attributes.put("auth.internalToken", "gateway-internal");
        }

        return new SecurityRequest(
                securityContext.principal(),
                clientIp,
                requestPath,
                requestMethod,
                Map.copyOf(attributes),
                Instant.now()
        );
    }

    private String exchangeAuthorizationValue(AuthAttempt authAttempt, RequestChannel requestChannel) {
        if (authAttempt.authMode() == AuthMode.JWT || authAttempt.authMode() == AuthMode.HYBRID) {
            if (requestChannel != null && !requestChannel.isWeb()) {
                return "gateway-authenticated";
            }
        }
        return null;
    }

    private SecurityContext buildSecurityContext(RouteType routeType, AuthAttempt authAttempt) {
        if (routeType == RouteType.INTERNAL) {
            return authAttempt.authenticated()
                    ? new SecurityContext(true, "gateway-internal", java.util.Set.of("INTERNAL"), Map.of())
                    : new SecurityContext(false, "", java.util.Set.of(), Map.of());
        }
        if (!authAttempt.authenticated() || authAttempt.authResult() == null) {
            return new SecurityContext(false, "", java.util.Set.of(), Map.of());
        }

        AuthResult authResult = authAttempt.authResult();
        LinkedHashSet<String> roles = new LinkedHashSet<>();
        if (authResult.getRole() != null && !authResult.getRole().isBlank()) {
            roles.add(authResult.getRole());
        }

        LinkedHashMap<String, String> attributes = new LinkedHashMap<>();
        if (authResult.getSessionId() != null && !authResult.getSessionId().isBlank()) {
            attributes.put("auth.sessionId", authResult.getSessionId());
        }
        if (authResult.getStatus() != null && !authResult.getStatus().isBlank()) {
            attributes.put(GatewayPlatformSecurityConfiguration.ATTR_USER_STATUS, authResult.getStatus());
        }
        attributes.put("gateway.auth.outcome", authAttempt.authOutcome());

        return new SecurityContext(
                true,
                authResult.getUserId(),
                java.util.Set.copyOf(roles),
                Map.copyOf(attributes)
        );
    }

    private RequestChannel resolveRequestChannel(ServerWebExchange exchange, String requestPath, RouteType routeType) {
        String clientTypeHeader = exchange.getRequest().getHeaders().getFirst(ExternalApiHeaders.CLIENT_TYPE);
        RequestChannel fromClientType = RequestChannel.fromClientType(clientTypeHeader);
        if (clientTypeHeader != null && !clientTypeHeader.isBlank() && fromClientType == null) {
            throw new GatewayException(GatewayErrorCode.INVALID_CLIENT_TYPE);
        }
        if (fromClientType != null) {
            return fromClientType;
        }
        String origin = exchange.getRequest().getHeaders().getFirst("Origin");
        if (origin != null && !origin.isBlank()) {
            return RequestChannel.WEB;
        }
        String referer = exchange.getRequest().getHeaders().getFirst("Referer");
        if (referer != null && !referer.isBlank()) {
            return RequestChannel.WEB;
        }
        RequestChannel fromUserAgent = resolveRequestChannelFromUserAgent(
                exchange.getRequest().getHeaders().getFirst(HttpHeaders.USER_AGENT)
        );
        if (fromUserAgent != null) {
            return fromUserAgent;
        }
        if (routeType == RouteType.PROTECTED || routeType == RouteType.ADMIN) {
            return RequestChannel.WEB;
        }
        return RequestChannel.API;
    }

    private String resolveIncomingAuth(
            RequestChannel requestChannel,
            ServerWebExchange exchange,
            String requestId,
            String correlationId
    ) throws IOException, InterruptedException {
        if (requestChannel == null) {
            return null;
        }
        if (requestChannel.isWeb()) {
            String cookieHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.COOKIE);
            if (extractCookieValue(cookieHeader, "sso_session") != null) {
                return null;
            }
            String accessToken = extractCookieValue(cookieHeader, "ACCESS_TOKEN");
            if (accessToken != null && !accessToken.isBlank()) {
                return "Bearer " + accessToken;
            }
            return null;
        }
        String authorizationHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (hasBearerToken(authorizationHeader)) {
            return authorizationHeader;
        }
        if (hasBasicToken(authorizationHeader)) {
            return authSessionValidator.exchangeBasicForBearer(authorizationHeader, requestId, correlationId);
        }
        return null;
    }

    private AuthMode resolvePlatformAuthMode(RequestChannel requestChannel, boolean bearerVerified) {
        if (bearerVerified) {
            return AuthMode.JWT;
        }
        if (requestChannel != null && requestChannel.isWeb()) {
            return AuthMode.SESSION;
        }
        return AuthMode.HYBRID;
    }

    private ClientType mapClientType(RouteType routeType, RequestChannel requestChannel) {
        if (routeType == RouteType.INTERNAL) {
            return ClientType.INTERNAL_SERVICE;
        }
        if (routeType == RouteType.ADMIN && (requestChannel == null || requestChannel.isWeb())) {
            return ClientType.ADMIN_CONSOLE;
        }
        if (requestChannel != null && requestChannel.isWeb()) {
            return ClientType.BROWSER;
        }
        return ClientType.EXTERNAL_API;
    }

    private SecurityBoundaryType mapBoundary(RouteType routeType) {
        return switch (routeType) {
            case PUBLIC -> SecurityBoundaryType.PUBLIC;
            case PROTECTED -> SecurityBoundaryType.PROTECTED;
            case ADMIN -> SecurityBoundaryType.ADMIN;
            case INTERNAL -> SecurityBoundaryType.INTERNAL;
        };
    }

    private Mono<Void> writeGatewayFailure(
            ServerWebExchange exchange,
            RouteMatch match,
            String requestMethod,
            String requestPath,
            String clientIp,
            long startedAt,
            GatewayErrorCode errorCode
    ) {
        exchange.getAttributes().put(GatewaySecurityExchangeAttributes.FAILURE_ERROR_CODE, errorCode);
        SecurityFailureResponse failureResponse = new SecurityFailureResponse(
                errorCode.getHttpStatus(),
                "gateway." + errorCode.getCode(),
                errorCode.getMessage()
        );
        return failureResponseWriter.write(exchange, failureResponse)
                .doOnSuccess(ignored -> recordDenied(
                        exchange,
                        SecurityDecision.gatewayFailure(match, requestMethod, requestPath, errorCode),
                        startedAt,
                        clientIp
                ));
    }

    private void recordDenied(ServerWebExchange exchange, SecurityDecision decision, long startedAt, String clientIp) {
        int status = exchange.getResponse().getStatusCode() == null
                ? 500
                : exchange.getResponse().getStatusCode().value();
        metrics.recordRequest(
                decision.requestMethod(),
                decision.match() == null ? "gateway" : decision.match().route().upstreamName(),
                status,
                decision.authOutcome(),
                Math.max(System.currentTimeMillis() - startedAt, 0)
        );
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

    private String resolveClientIp(ServerWebExchange exchange) {
        InetSocketAddress remoteAddress = exchange.getRequest().getRemoteAddress();
        if (remoteAddress == null || remoteAddress.getAddress() == null) {
            return "";
        }
        return remoteAddress.getAddress().getHostAddress();
    }

    private String resolveRequestId(ServerWebExchange exchange) {
        Object attribute = exchange.getAttribute(GatewayCommonWebFilter.REQUEST_ID_ATTR);
        if (attribute instanceof String value && !value.isBlank()) {
            return value;
        }
        String headerValue = exchange.getRequest().getHeaders().getFirst(TraceHeaders.REQUEST_ID);
        return headerValue == null ? "" : headerValue;
    }

    private String resolveCorrelationId(ServerWebExchange exchange) {
        Object attribute = exchange.getAttribute(GatewayCommonWebFilter.CORRELATION_ID_ATTR);
        if (attribute instanceof String value && !value.isBlank()) {
            return value;
        }
        String headerValue = exchange.getRequest().getHeaders().getFirst(TraceHeaders.CORRELATION_ID);
        return headerValue == null ? "" : headerValue;
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
            return value.isBlank() ? null : value;
        }
        return null;
    }

    private boolean hasBearerToken(String authorizationHeader) {
        return authorizationHeader != null && !authorizationHeader.isBlank() && authorizationHeader.startsWith("Bearer ");
    }

    private boolean hasBasicToken(String authorizationHeader) {
        return authorizationHeader != null
                && !authorizationHeader.isBlank()
                && authorizationHeader.regionMatches(true, 0, "Basic ", 0, "Basic ".length());
    }

    private boolean hasCookieBasedAuth(String cookieHeader) {
        return cookieHeader != null
                && !cookieHeader.isBlank()
                && (cookieHeader.contains("ACCESS_TOKEN=") || cookieHeader.contains("sso_session="));
    }

    private RequestChannel resolveRequestChannelFromUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return null;
        }
        String normalized = userAgent.toLowerCase(Locale.ROOT);
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

    private static boolean hasUserId(AuthResult authResult) {
        return authResult.getUserId() != null && !authResult.getUserId().isBlank();
    }

    private record AuthAttempt(
            boolean authenticated,
            AuthResult authResult,
            String authOutcome,
            AuthMode authMode,
            GatewayErrorCode failureCode
    ) {
        private static AuthAttempt anonymous(String authOutcome) {
            return new AuthAttempt(false, null, authOutcome, AuthMode.NONE, null);
        }

        private static AuthAttempt internal() {
            return new AuthAttempt(true, null, "INTERNAL_SECRET", AuthMode.HYBRID, null);
        }

        private static AuthAttempt authenticated(AuthResult authResult, String authOutcome, AuthMode authMode) {
            return new AuthAttempt(true, authResult, authOutcome, authMode, null);
        }

        private static AuthAttempt failed(String authOutcome, AuthMode authMode, GatewayErrorCode failureCode) {
            return new AuthAttempt(false, null, authOutcome, authMode, failureCode);
        }
    }

    private record SecurityDecision(
            boolean allowed,
            RouteMatch match,
            String requestMethod,
            String requestPath,
            String authOutcome,
            AuthResult authResult,
            RequestChannel requestChannel,
            SecurityEvaluationResult evaluationResult,
            SecurityFailureResponse failureResponse,
            String failureReason
    ) {
        private static SecurityDecision allowed(
                RouteMatch match,
                String requestMethod,
                String requestPath,
                String authOutcome,
                AuthResult authResult,
                RequestChannel requestChannel,
                SecurityEvaluationResult evaluationResult
        ) {
            return new SecurityDecision(true, match, requestMethod, requestPath, authOutcome, authResult, requestChannel, evaluationResult, null, "");
        }

        private static SecurityDecision denied(
                RouteMatch match,
                String requestMethod,
                String requestPath,
                String authOutcome,
                AuthResult authResult,
                RequestChannel requestChannel,
                SecurityEvaluationResult evaluationResult,
                SecurityFailureResponse failureResponse,
                GatewayErrorCode failureCode
        ) {
            String reason = failureCode == null
                    ? evaluationResult.verdict().policy()
                    : failureCode.name();
            return new SecurityDecision(false, match, requestMethod, requestPath, authOutcome, authResult, requestChannel, evaluationResult, failureResponse, reason);
        }

        private static SecurityDecision gatewayFailure(
                RouteMatch match,
                String requestMethod,
                String requestPath,
                GatewayErrorCode failureCode
        ) {
            return new SecurityDecision(false, match, requestMethod, requestPath, failureCode.name(), null, null, null, null, failureCode.name());
        }
    }
}
