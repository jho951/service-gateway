package com.gateway.spring;

import com.gateway.GatewayApplication;
import com.gateway.config.GatewayConfig;
import com.gateway.config.RuntimeEnvironment;
import com.gateway.contract.internal.header.TraceHeaders;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.web.context.WebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GatewaySpringIntegrationTest {
    private HttpServer authServer;
    private HttpServer userServer;
    private HttpServer blockServer;
    private HttpServer authzServer;
    private ConfigurableApplicationContext gatewayContext;
    private Path envFile;

    @AfterEach
    void tearDown() throws IOException {
        if (gatewayContext != null) {
            gatewayContext.close();
        }
        stopServer(authServer);
        stopServer(userServer);
        stopServer(blockServer);
        stopServer(authzServer);
        if (envFile != null) {
            Files.deleteIfExists(envFile);
        }
    }

    @Test
    void healthReturnsOkWithTraceHeaders() throws Exception {
        startUpstreams(new AtomicInteger(), "user-123", new AtomicInteger(), null, null, null, null, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest("/health", null, null, Map.of());

        assertEquals(200, response.statusCode());
        assertEquals("{\"status\":\"UP\"}", response.body());
        assertNotNull(response.headers().firstValue(TraceHeaders.REQUEST_ID).orElse(null));
        assertNotNull(response.headers().firstValue(TraceHeaders.CORRELATION_ID).orElse(null));
    }

    @Test
    void protectedRouteWithoutCredentialsReturnsGatewayUnauthorized() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        startUpstreams(validateCalls, "user-123", blockCalls, null, null, null, null, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest("/v1/documents/doc-1", null, null, Map.of());

        assertEquals(401, response.statusCode());
        assertEquals(0, validateCalls.get());
        assertEquals(0, blockCalls.get());
        assertTrue(response.body().contains("\"code\":\"1003\""), response.body());
        assertTrue(response.body().contains("\"path\":\"/v1/documents/doc-1\""), response.body());
        assertNotNull(response.headers().firstValue(TraceHeaders.REQUEST_ID).orElse(null));
    }

    @Test
    void protectedRouteWithBearerValidatesAndForwardsInternalJwt() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicReference<String> authHeaderSeenByBlock = new AtomicReference<>();
        AtomicReference<String> userIdHeaderSeenByBlock = new AtomicReference<>();
        AtomicReference<String> internalSecretHeaderSeenByAuth = new AtomicReference<>();

        startUpstreams(validateCalls, "user-123", blockCalls, exchange -> {
            authHeaderSeenByBlock.set(exchange.getRequestHeaders().getFirst("Authorization"));
            userIdHeaderSeenByBlock.set(exchange.getRequestHeaders().getFirst("X-User-Id"));
            writeJson(exchange, 200, "{\"ok\":true}");
        }, exchange -> {
            internalSecretHeaderSeenByAuth.set(exchange.getRequestHeaders().getFirst("X-Internal-Request-Secret"));
            writeJson(exchange, 200, "{\"authenticated\":true,\"userId\":\"user-123\",\"status\":\"A\"}");
        }, null, null, null);
        startGateway();

        String callerToken = "Bearer " + jwt("{\"sub\":\"user-123\",\"exp\":4102444800}");
        HttpResponse<String> response = sendGatewayRequest(
                "/v1/documents/doc-1",
                callerToken,
                null,
                Map.of("X-Client-Type", "api")
        );

        assertEquals(200, response.statusCode());
        assertEquals(1, validateCalls.get());
        assertEquals(1, blockCalls.get());
        assertEquals("local-internal-api-key", internalSecretHeaderSeenByAuth.get());
        assertEquals("user-123", userIdHeaderSeenByBlock.get());
        assertNotNull(authHeaderSeenByBlock.get());
        assertTrue(authHeaderSeenByBlock.get().startsWith("Bearer "));
        assertNotEquals(callerToken, authHeaderSeenByBlock.get());
        assertEquals("A", jwtClaim(authHeaderSeenByBlock.get(), "status"));
    }

    @Test
    void blockAttachmentRouteForwardsToEditorService() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicReference<String> editorPath = new AtomicReference<>();

        startUpstreams(validateCalls, "user-123", blockCalls, exchange -> {
            editorPath.set(exchange.getRequestURI().getPath());
            writeJson(exchange, 200, "{\"ok\":true}");
        }, null, null, null, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest(
                "/v1/blocks/block-1/attachments/att-1",
                "Bearer " + jwt("{\"sub\":\"user-123\",\"exp\":4102444800}"),
                null,
                Map.of("X-Client-Type", "api")
        );

        assertEquals(200, response.statusCode());
        assertEquals(1, validateCalls.get());
        assertEquals(1, blockCalls.get());
        assertEquals("/blocks/block-1/attachments/att-1", editorPath.get());
    }

    @Test
    void authAliasesForwardToAuthServiceUpstream() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger loginGithubCalls = new AtomicInteger();
        AtomicInteger meCalls = new AtomicInteger();
        AtomicReference<String> userIdHeaderSeenByAuthMe = new AtomicReference<>();

        startUpstreams(
                validateCalls,
                "user-123",
                new AtomicInteger(),
                null,
                null,
                exchange -> {
                    meCalls.incrementAndGet();
                    userIdHeaderSeenByAuthMe.set(exchange.getRequestHeaders().getFirst("X-User-Id"));
                    writeJson(exchange, 200, "{\"userId\":\"user-123\",\"status\":\"A\"}");
                },
                null,
                null
        );
        authServer.createContext("/auth/login/github", exchange -> {
            loginGithubCalls.incrementAndGet();
            writeJson(exchange, 200, "{\"redirect\":true}");
        });
        startGateway();

        String accessToken = jwt("{\"sub\":\"user-123\",\"exp\":4102444800}");

        HttpResponse<String> loginGithubResponse = sendGatewayRequest("/v1/auth/login/github", null, null, Map.of());
        HttpResponse<String> meResponse = sendGatewayRequest(
                "/v1/auth/me?page=explain",
                null,
                "sso_session=session-1; ACCESS_TOKEN=" + accessToken,
                Map.of(
                        "Origin", "http://localhost:5173",
                        "X-Client-Type", "web"
                )
        );

        assertEquals(200, loginGithubResponse.statusCode(), loginGithubResponse.body());
        assertEquals(200, meResponse.statusCode(), meResponse.body());
        assertEquals(1, loginGithubCalls.get());
        assertEquals(1, meCalls.get());
        assertEquals(1, validateCalls.get());
        assertEquals("user-123", userIdHeaderSeenByAuthMe.get());
    }

    @Test
    void loginRouteIsRateLimitedByPlatformPolicy() throws Exception {
        startUpstreams(new AtomicInteger(), "user-123", new AtomicInteger(), null, null, null, null, null);
        startGateway(Map.of("GATEWAY_LOGIN_RATE_LIMIT_PER_MINUTE", "1"));

        HttpResponse<String> first = sendGatewayPost("/v1/auth/login", "{}", Map.of("Content-Type", "application/json"));
        HttpResponse<String> second = sendGatewayPost("/v1/auth/login", "{}", Map.of("Content-Type", "application/json"));

        assertEquals(200, first.statusCode());
        assertEquals(429, second.statusCode());
        assertTrue(second.body().contains("\"code\":\"1010\""), second.body());
    }

    @Test
    void usersMePassesThroughInactiveUserForbidden() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicInteger userCalls = new AtomicInteger();
        AtomicReference<String> userIdHeaderSeenByUser = new AtomicReference<>();

        startUpstreams(
                validateCalls,
                "user-inactive",
                blockCalls,
                null,
                null,
                null,
                null,
                exchange -> {
                    userCalls.incrementAndGet();
                    userIdHeaderSeenByUser.set(exchange.getRequestHeaders().getFirst("X-User-Id"));
                    writeJson(exchange, 403, "{\"code\":7004,\"message\":\"접근 권한이 없습니다.\"}");
                }
        );
        startGateway();

        HttpResponse<String> response = sendGatewayRequest(
                "/v1/users/me",
                null,
                "sso_session=session-inactive; Path=/; HttpOnly",
                Map.of("Origin", "http://localhost:5173")
        );

        assertEquals(403, response.statusCode());
        assertEquals(1, validateCalls.get());
        assertEquals(0, blockCalls.get());
        assertEquals(1, userCalls.get());
        assertEquals("user-inactive", userIdHeaderSeenByUser.get());
        assertEquals("{\"code\":7004,\"message\":\"접근 권한이 없습니다.\"}", response.body());
    }

    @Test
    void adminRouteChecksAuthzBeforeForwarding() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicInteger authzCalls = new AtomicInteger();
        AtomicReference<String> originalMethod = new AtomicReference<>();
        AtomicReference<String> originalPath = new AtomicReference<>();
        AtomicReference<String> authzAuthorization = new AtomicReference<>();
        AtomicReference<String> blockPath = new AtomicReference<>();

        startAuthzServer(exchange -> {
            authzCalls.incrementAndGet();
            originalMethod.set(exchange.getRequestHeaders().getFirst("X-Original-Method"));
            originalPath.set(exchange.getRequestHeaders().getFirst("X-Original-Path"));
            authzAuthorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            writeJson(exchange, 200, "{\"allowed\":true}");
        });
        startUpstreams(validateCalls, "admin-123", blockCalls, exchange -> {
            blockPath.set(exchange.getRequestURI().getPath());
            writeJson(exchange, 200, "{\"ok\":true}");
        }, exchange -> writeJson(
                exchange,
                200,
                "{\"authenticated\":true,\"userId\":\"admin-123\",\"role\":\"ADMIN\",\"status\":\"A\",\"sessionId\":\"session-admin\"}"
        ), null, null, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest(
                "/v1/admin/dashboard",
                null,
                "sso_session=session-admin; Path=/; HttpOnly",
                Map.of("Origin", "http://localhost:5173")
        );

        assertEquals(200, response.statusCode());
        assertEquals(1, validateCalls.get());
        assertEquals(1, authzCalls.get());
        assertEquals(1, blockCalls.get());
        assertEquals("GET", originalMethod.get());
        assertEquals("/v1/admin/dashboard", originalPath.get());
        assertNotNull(authzAuthorization.get());
        assertTrue(authzAuthorization.get().startsWith("Bearer "));
        assertEquals("api-gateway", jwtClaim(authzAuthorization.get(), "sub"));
        assertEquals("api-gateway", jwtClaim(authzAuthorization.get(), "iss"));
        assertEquals("authz-service", jwtClaim(authzAuthorization.get(), "aud"));
        assertEquals("/admin/dashboard", blockPath.get());
    }

    @Test
    void adminRouteDeniedWhenAuthzRejects() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicInteger authzCalls = new AtomicInteger();

        startAuthzServer(exchange -> {
            authzCalls.incrementAndGet();
            exchange.sendResponseHeaders(403, -1);
            exchange.close();
        });
        startUpstreams(validateCalls, "admin-123", blockCalls, exchange -> writeJson(exchange, 200, "{\"ok\":true}"), exchange -> writeJson(
                exchange,
                200,
                "{\"authenticated\":true,\"userId\":\"admin-123\",\"role\":\"ADMIN\",\"status\":\"A\",\"sessionId\":\"session-admin\"}"
        ), null, null, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest(
                "/v1/admin/dashboard",
                null,
                "sso_session=session-admin; Path=/; HttpOnly",
                Map.of("Origin", "http://localhost:5173")
        );

        assertEquals(403, response.statusCode());
        assertEquals(1, validateCalls.get());
        assertEquals(1, authzCalls.get());
        assertEquals(0, blockCalls.get());
        assertTrue(response.body().contains("\"code\":\"1006\""), response.body());
    }

    @Test
    void internalRouteIsNotExposedPublicly() throws Exception {
        startUpstreams(new AtomicInteger(), "user-123", new AtomicInteger(), null, null, null, null, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest("/v1/internal/ping", null, null, Map.of());

        assertEquals(404, response.statusCode());
        assertTrue(response.body().contains("\"code\":\"1007\""), response.body());
    }

    @Test
    void unknownRouteReturnsGatewayErrorResponse() throws Exception {
        startUpstreams(new AtomicInteger(), "user-123", new AtomicInteger(), null, null, null, null, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest("/v1/unknown", null, null, Map.of());

        assertEquals(404, response.statusCode());
        assertTrue(response.body().contains("\"code\":\"1007\""), response.body());
        assertTrue(response.body().contains("\"path\":\"/v1/unknown\""), response.body());
        assertNotNull(response.headers().firstValue(TraceHeaders.REQUEST_ID).orElse(null));
        assertNotNull(response.headers().firstValue(TraceHeaders.CORRELATION_ID).orElse(null));
    }

    @Test
    void actuatorPrometheusExposesMicrometerMetrics() throws Exception {
        startUpstreams(new AtomicInteger(), "user-123", new AtomicInteger(), null, null, null, null, null);
        startGateway();

        sendGatewayRequest("/health", null, null, Map.of());
        HttpResponse<String> response = sendGatewayRequest("/actuator/prometheus", null, null, Map.of());

        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("jvm_memory_used_bytes"), response.body());
    }

    @Test
    void upstreamUnavailableReturnsGatewayBadGateway() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        startUpstreams(validateCalls, "user-123", new AtomicInteger(), null, null, null, null, null);
        stopServer(blockServer);
        blockServer = null;

        int unavailablePort = findFreePort();
        startGateway(Map.of("EDITOR_SERVICE_URL", "http://127.0.0.1:" + unavailablePort));

        HttpResponse<String> response = sendGatewayRequest(
                "/v1/documents/doc-1",
                "Bearer " + jwt("{\"sub\":\"user-123\",\"exp\":4102444800}"),
                null,
                Map.of("X-Client-Type", "api")
        );

        assertEquals(502, response.statusCode());
        assertTrue(response.body().contains("\"code\":\"1012\""), response.body());
        assertTrue(response.body().contains("\"path\":\"/v1/documents/doc-1\""), response.body());
    }

    @Test
    void upstreamTimeoutReturnsGatewayTimeout() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        startUpstreams(validateCalls, "user-123", new AtomicInteger(), exchange -> {
            try {
                Thread.sleep(800);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }
            writeJson(exchange, 200, "{\"ok\":true}");
        }, null, null, null, null);
        startGateway(Map.of("GATEWAY_REQUEST_TIMEOUT_MS", "200"));

        HttpResponse<String> response = sendGatewayRequest(
                "/v1/documents/doc-1",
                "Bearer " + jwt("{\"sub\":\"user-123\",\"exp\":4102444800}"),
                null,
                Map.of("X-Client-Type", "api")
        );

        assertEquals(504, response.statusCode());
        assertTrue(response.body().contains("\"code\":\"1013\""), response.body());
        assertTrue(response.body().contains("\"path\":\"/v1/documents/doc-1\""), response.body());
    }

    private void startUpstreams(
            AtomicInteger validateCalls,
            String validatedUserId,
            AtomicInteger blockCalls,
            HttpHandler blockHandler,
            HttpHandler authValidateHandler,
            HttpHandler authMeHandler,
            HttpHandler authSsoStartHandler,
            HttpHandler userHandler
    ) throws IOException {
        authServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        authServer.createContext("/auth/internal/session/validate", exchange -> {
            validateCalls.incrementAndGet();
            if (authValidateHandler != null) {
                authValidateHandler.handle(exchange);
                return;
            }
            if (validatedUserId == null) {
                writeJson(exchange, 401, "{\"authenticated\":false}");
                return;
            }
            writeJson(exchange, 200, "{\"authenticated\":true,\"userId\":\"" + validatedUserId + "\",\"status\":\"A\"}");
        });
        authServer.createContext("/auth/login", exchange -> {
            if (validatedUserId == null) {
                writeJson(exchange, 401, "{\"authenticated\":false}");
                return;
            }
            String accessToken = jwt("{\"sub\":\"" + validatedUserId + "\",\"exp\":4102444800}");
            writeJson(exchange, 200, "{\"accessToken\":\"" + accessToken + "\",\"refreshToken\":\"refresh-token\"}");
        });
        authServer.createContext("/auth/me", exchange -> {
            if (authMeHandler != null) {
                authMeHandler.handle(exchange);
                return;
            }
            if (validatedUserId == null) {
                writeJson(exchange, 401, "{\"userId\":null}");
                return;
            }
            writeJson(exchange, 200, "{\"userId\":\"" + validatedUserId + "\",\"status\":\"A\"}");
        });
        authServer.createContext("/auth/sso/start", exchange -> {
            if (authSsoStartHandler != null) {
                authSsoStartHandler.handle(exchange);
                return;
            }
            writeJson(exchange, 200, "{\"ok\":true}");
        });
        authServer.createContext("/internal/ping", exchange -> writeJson(exchange, 200, "{\"ok\":true}"));
        authServer.start();

        userServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        userServer.createContext("/", exchange -> {
            if (userHandler != null) {
                userHandler.handle(exchange);
                return;
            }
            writeJson(exchange, 200, "{\"ok\":true}");
        });
        userServer.start();

        blockServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        HttpHandler blockEntry = exchange -> {
            blockCalls.incrementAndGet();
            if (blockHandler != null) {
                blockHandler.handle(exchange);
                return;
            }
            writeJson(exchange, 200, "{\"ok\":true}");
        };
        blockServer.createContext("/documents", blockEntry);
        blockServer.createContext("/blocks", blockEntry);
        blockServer.createContext("/editor-operations", blockEntry);
        blockServer.createContext("/admin", blockEntry);
        blockServer.start();
    }

    private void startAuthzServer(HttpHandler authzHandler) throws IOException {
        authzServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        authzServer.createContext("/permissions/internal/admin/verify", exchange -> {
            if (authzHandler != null) {
                authzHandler.handle(exchange);
                return;
            }
            writeJson(exchange, 200, "{\"allowed\":true}");
        });
        authzServer.start();
    }

    private void startGateway() throws IOException {
        startGateway(Map.of());
    }

    private void startGateway(Map<String, String> overrides) throws IOException {
        LinkedHashMap<String, String> env = new LinkedHashMap<>();
        env.put("GATEWAY_BIND", "127.0.0.1");
        env.put("GATEWAY_PORT", "0");
        env.put("GATEWAY_IP_GUARD_ENABLED", "false");
        env.put("GATEWAY_INTERNAL_IP_GUARD_ENABLED", "false");
        env.put("GATEWAY_ADMIN_IP_GUARD_ENABLED", "false");
        env.put("GATEWAY_AUTHZ_CACHE_ENABLED", "false");
        env.put("AUTH_JWT_VERIFY_ENABLED", "false");
        env.put("AUTH_SERVICE_INTERNAL_REQUEST_SECRET", "local-internal-api-key");
        env.put("AUTH_SERVICE_URL", "http://127.0.0.1:" + authServer.getAddress().getPort());
        env.put("USER_SERVICE_URL", "http://127.0.0.1:" + userServer.getAddress().getPort());
        if (blockServer != null) {
            env.put("EDITOR_SERVICE_URL", "http://127.0.0.1:" + blockServer.getAddress().getPort());
        }
        if (authzServer != null) {
            String authzBase = "http://127.0.0.1:" + authzServer.getAddress().getPort();
            env.put("AUTHZ_ADMIN_VERIFY_URL", authzBase + "/permissions/internal/admin/verify");
        }
        env.putAll(overrides);

        envFile = Files.createTempFile("gateway-test-", ".env");
        Files.writeString(envFile, toEnvFile(env), StandardCharsets.UTF_8);

        String[] args = {
                "--profile=test",
                "--env-file=" + envFile.toAbsolutePath()
        };
        RuntimeEnvironment.ResolvedEnvironment runtimeEnvironment = RuntimeEnvironment.load(args);
        GatewayConfig config = GatewayConfig.fromEnv(runtimeEnvironment.variables());
        Map<String, Object> defaults = new LinkedHashMap<>(runtimeEnvironment.variables());
        defaults.put("server.address", config.bindAddress().getHostString());
        defaults.put("server.port", String.valueOf(config.bindAddress().getPort()));
        defaults.put("spring.application.name", "gateway-service");
        defaults.put("spring.main.web-application-type", "reactive");
        defaults.put("spring.cloud.gateway.server.webflux.forwarded.enabled", "true");
        defaults.put("management.endpoints.web.exposure.include", "health,info,metrics,prometheus");
        defaults.put("management.endpoint.health.probes.enabled", "true");

        SpringApplication application = new SpringApplication(GatewayApplication.class);
        application.setDefaultProperties(defaults);
        gatewayContext = application.run(args);
    }

    private HttpResponse<String> sendGatewayRequest(
            String path,
            String authorizationHeader,
            String cookieHeader,
            Map<String, String> extraHeaders
    ) throws Exception {
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + gatewayPort() + path))
                .timeout(Duration.ofSeconds(3))
                .GET();
        if (authorizationHeader != null) {
            requestBuilder.header("Authorization", authorizationHeader);
        }
        if (cookieHeader != null) {
            requestBuilder.header("Cookie", cookieHeader);
        }
        for (Map.Entry<String, String> header : extraHeaders.entrySet()) {
            requestBuilder.header(header.getKey(), header.getValue());
        }
        return HttpClient.newHttpClient().send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> sendGatewayPost(
            String path,
            String body,
            Map<String, String> extraHeaders
    ) throws Exception {
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + gatewayPort() + path))
                .timeout(Duration.ofSeconds(3))
                .POST(HttpRequest.BodyPublishers.ofString(body == null ? "" : body, StandardCharsets.UTF_8));
        for (Map.Entry<String, String> header : extraHeaders.entrySet()) {
            requestBuilder.header(header.getKey(), header.getValue());
        }
        return HttpClient.newHttpClient().send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private int gatewayPort() {
        return ((WebServerApplicationContext) gatewayContext).getWebServer().getPort();
    }

    private static String toEnvFile(Map<String, String> env) {
        StringBuilder builder = new StringBuilder();
        for (Map.Entry<String, String> entry : env.entrySet()) {
            builder.append(entry.getKey()).append('=').append(entry.getValue()).append('\n');
        }
        return builder.toString();
    }

    private static void writeJson(HttpExchange exchange, int statusCode, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        } finally {
            exchange.close();
        }
    }

    private static void stopServer(HttpServer server) {
        if (server != null) {
            server.stop(0);
        }
    }

    private static int findFreePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static String jwt(String payloadJson) {
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("sig".getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + "." + signature;
    }

    private static String jwtClaim(String jwt, String claimName) {
        String[] parts = jwt.split("\\.", -1);
        if (parts.length != 3) {
            return null;
        }
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        String needle = "\"" + claimName + "\":\"";
        int start = payloadJson.indexOf(needle);
        if (start < 0) {
            return null;
        }
        start += needle.length();
        int end = payloadJson.indexOf('"', start);
        if (end < 0) {
            return null;
        }
        return payloadJson.substring(start, end);
    }
}
