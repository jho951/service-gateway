package com.gateway.server;

import com.gateway.config.GatewayConfig;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Gateway 인증/프록시 경로의 통합 동작을 검증하는 테스트입니다. */
class GatewayHandlerAuthIntegrationTest {
    private HttpServer authServer;
    private HttpServer userServer;
    private HttpServer blockServer;
    private HttpServer permissionServer;
    private HttpServer gatewayServer;

    @AfterEach
    void tearDown() {
        stopServer(gatewayServer);
        stopServer(authServer);
        stopServer(userServer);
        stopServer(blockServer);
        stopServer(permissionServer);
    }

    @Test
    void documentsWithoutBearerAndCookieReturnsUnauthorized() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        startUpstreams(validateCalls, "user-123", blockCalls, null, null, null, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest("/v1/documents/doc-1", null, null);

        assertEquals(401, response.statusCode());
        assertEquals(0, validateCalls.get());
        assertEquals(0, blockCalls.get());
    }

    @Test
    void documentsWithBearerValidatesAndForwardsInternalJwt() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicReference<String> authHeaderSeenByBlock = new AtomicReference<>();
        AtomicReference<String> userIdHeaderSeenByBlock = new AtomicReference<>();
        AtomicReference<String> userStatusHeaderSeenByBlock = new AtomicReference<>();
        startUpstreams(validateCalls, "user-123", blockCalls, exchange -> {
            authHeaderSeenByBlock.set(exchange.getRequestHeaders().getFirst("Authorization"));
            userIdHeaderSeenByBlock.set(exchange.getRequestHeaders().getFirst("X-User-Id"));
            userStatusHeaderSeenByBlock.set(exchange.getRequestHeaders().getFirst("X-User-Status"));
            writeJson(exchange, 200, "{\"ok\":true}");
        }, null, null, null);
        startGateway();

        String validShapeToken = "Bearer " + jwt("{\"sub\":\"user-123\",\"exp\":4102444800}");
        HttpResponse<String> response = sendGatewayRequest(
                "/v1/documents/doc-1",
                validShapeToken,
                null,
                Map.of("X-Client-Type", "api")
        );

        assertEquals(200, response.statusCode());
        assertEquals(1, validateCalls.get());
        assertEquals(1, blockCalls.get());
        assertNotNull(authHeaderSeenByBlock.get());
        assertTrue(authHeaderSeenByBlock.get().startsWith("Bearer "));
        assertNotEquals(validShapeToken, authHeaderSeenByBlock.get());
        assertEquals("user-123", userIdHeaderSeenByBlock.get());
        assertEquals("A", userStatusHeaderSeenByBlock.get());
        assertEquals("A", jwtClaim(authHeaderSeenByBlock.get(), "status"));
    }

    @Test
    void editorOperationRouteRewritesV1PrefixAndForwardsToEditorServer() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicReference<String> blockMethod = new AtomicReference<>();
        AtomicReference<String> blockPath = new AtomicReference<>();
        AtomicReference<String> userIdHeaderSeenByBlock = new AtomicReference<>();
        startUpstreams(validateCalls, "editor-user", blockCalls, exchange -> {
            blockMethod.set(exchange.getRequestMethod());
            blockPath.set(exchange.getRequestURI().getPath());
            userIdHeaderSeenByBlock.set(exchange.getRequestHeaders().getFirst("X-User-Id"));
            writeJson(exchange, 200, "{\"ok\":true}");
        }, null, null, null);
        startGateway();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + gatewayServer.getAddress().getPort()
                        + "/v1/editor-operations/documents/00000000-0000-0000-0000-000000000001/save"))
                .timeout(Duration.ofSeconds(3))
                .header("Cookie", "sso_session=session-editor; Path=/; HttpOnly")
                .header("Origin", "http://localhost:5173")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"batchId\":\"batch-1\",\"operations\":[]}"))
                .build();

        HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode());
        assertEquals(1, validateCalls.get());
        assertEquals(1, blockCalls.get());
        assertEquals("POST", blockMethod.get());
        assertEquals("/editor-operations/documents/00000000-0000-0000-0000-000000000001/save", blockPath.get());
        assertEquals("editor-user", userIdHeaderSeenByBlock.get());
    }

    @Test
    void workspacesRouteRewritesV1PrefixAndForwardsToEditorServer() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicReference<String> blockPath = new AtomicReference<>();
        AtomicReference<String> userIdHeaderSeenByBlock = new AtomicReference<>();
        startUpstreams(validateCalls, "workspace-user", blockCalls, exchange -> {
            blockPath.set(exchange.getRequestURI().getPath());
            userIdHeaderSeenByBlock.set(exchange.getRequestHeaders().getFirst("X-User-Id"));
            writeJson(exchange, 200, "{\"ok\":true}");
        }, null, null, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest(
                "/v1/workspaces/00000000-0000-0000-0000-000000000002",
                null,
                "sso_session=session-workspace; Path=/; HttpOnly",
                Map.of("Origin", "http://localhost:5173")
        );

        assertEquals(200, response.statusCode());
        assertEquals(1, validateCalls.get());
        assertEquals(1, blockCalls.get());
        assertEquals("/workspaces/00000000-0000-0000-0000-000000000002", blockPath.get());
        assertEquals("workspace-user", userIdHeaderSeenByBlock.get());
    }

    @Test
    void documentsWithBasicExchangesToBearerValidatesAndForwardsInternalJwt() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicReference<String> authHeaderSeenByValidate = new AtomicReference<>();
        AtomicReference<String> authHeaderSeenByBlock = new AtomicReference<>();
        AtomicReference<String> userIdHeaderSeenByBlock = new AtomicReference<>();
        startUpstreams(validateCalls, "user-basic", blockCalls, exchange -> {
            authHeaderSeenByBlock.set(exchange.getRequestHeaders().getFirst("Authorization"));
            userIdHeaderSeenByBlock.set(exchange.getRequestHeaders().getFirst("X-User-Id"));
            writeJson(exchange, 200, "{\"ok\":true}");
        }, exchange -> {
            authHeaderSeenByValidate.set(exchange.getRequestHeaders().getFirst("Authorization"));
            writeJson(exchange, 200, "{\"authenticated\":true,\"userId\":\"user-basic\",\"status\":\"A\"}");
        }, null, null);
        startGateway();

        String basicCredential = Base64.getEncoder()
                .encodeToString("basic-user:basic-pass".getBytes(StandardCharsets.UTF_8));
        HttpResponse<String> response = sendGatewayRequest(
                "/v1/documents/doc-basic",
                "Basic " + basicCredential,
                null,
                Map.of("X-Client-Type", "api")
        );

        assertEquals(200, response.statusCode());
        assertEquals(1, validateCalls.get());
        assertEquals(1, blockCalls.get());
        assertNotNull(authHeaderSeenByValidate.get());
        assertTrue(authHeaderSeenByValidate.get().startsWith("Bearer "));
        assertNotNull(authHeaderSeenByBlock.get());
        assertTrue(authHeaderSeenByBlock.get().startsWith("Bearer "));
        assertEquals("user-basic", userIdHeaderSeenByBlock.get());
    }

    @Test
    void documentsWithRejectedBasicReturnsUnauthorizedWithoutValidation() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        startUpstreams(validateCalls, null, blockCalls, null, null, null, null);
        startGateway();

        String basicCredential = Base64.getEncoder()
                .encodeToString("bad-user:bad-pass".getBytes(StandardCharsets.UTF_8));
        HttpResponse<String> response = sendGatewayRequest(
                "/v1/documents/doc-basic",
                "Basic " + basicCredential,
                null,
                Map.of("X-Client-Type", "api")
        );

        assertEquals(401, response.statusCode());
        assertEquals(0, validateCalls.get());
        assertEquals(0, blockCalls.get());
    }

    @Test
    void documentsWithAccessTokenCookieValidatesAndForwardsInternalJwt() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicReference<String> authHeaderSeenByBlock = new AtomicReference<>();
        AtomicReference<String> userStatusHeaderSeenByBlock = new AtomicReference<>();
        startUpstreams(validateCalls, "user-456", blockCalls, exchange -> {
            authHeaderSeenByBlock.set(exchange.getRequestHeaders().getFirst("Authorization"));
            userStatusHeaderSeenByBlock.set(exchange.getRequestHeaders().getFirst("X-User-Status"));
            writeJson(exchange, 200, "{\"ok\":true}");
        }, null, null, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest(
                "/v1/documents/doc-2",
                null,
                "ACCESS_TOKEN=" + jwt("{\"sub\":\"user-456\",\"exp\":4102444800}") + "; Path=/; HttpOnly",
                Map.of("Origin", "http://localhost:5173")
        );

        assertEquals(200, response.statusCode());
        assertEquals(1, validateCalls.get());
        assertEquals(1, blockCalls.get());
        assertNotNull(authHeaderSeenByBlock.get());
        assertTrue(authHeaderSeenByBlock.get().startsWith("Bearer "));
        assertEquals("A", userStatusHeaderSeenByBlock.get());
    }

    @Test
    void documentsWithSsoSessionCookieValidatesAndForwardsInternalJwt() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicReference<String> authHeaderSeenByBlock = new AtomicReference<>();
        AtomicReference<String> userStatusHeaderSeenByBlock = new AtomicReference<>();
        AtomicReference<String> cookieSeenByValidate = new AtomicReference<>();
        startUpstreams(validateCalls, "user-789", blockCalls, exchange -> {
            authHeaderSeenByBlock.set(exchange.getRequestHeaders().getFirst("Authorization"));
            userStatusHeaderSeenByBlock.set(exchange.getRequestHeaders().getFirst("X-User-Status"));
            writeJson(exchange, 200, "{\"ok\":true}");
        }, exchange -> {
            cookieSeenByValidate.set(exchange.getRequestHeaders().getFirst("Cookie"));
            writeJson(exchange, 200, "{\"authenticated\":true,\"userId\":\"user-789\",\"status\":\"A\"}");
        }, null, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest(
                "/v1/documents/doc-3",
                null,
                "sso_session=session-789; Path=/; HttpOnly",
                Map.of("Origin", "http://localhost:5173")
        );

        assertEquals(200, response.statusCode());
        assertEquals(1, validateCalls.get());
        assertEquals(1, blockCalls.get());
        assertNotNull(authHeaderSeenByBlock.get());
        assertTrue(authHeaderSeenByBlock.get().startsWith("Bearer "));
        assertNotNull(cookieSeenByValidate.get());
        assertTrue(cookieSeenByValidate.get().contains("sso_session=session-789"));
        assertEquals("A", userStatusHeaderSeenByBlock.get());
    }

    @Test
    void documentsWithWebClientTypeAndBearerOnlyReturnsUnauthorized() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        startUpstreams(validateCalls, "user-123", blockCalls, null, null, null, null);
        startGateway();

        String validShapeToken = "Bearer " + jwt("{\"sub\":\"user-123\",\"exp\":4102444800}");
        HttpResponse<String> response = sendGatewayRequest(
                "/v1/documents/doc-1",
                validShapeToken,
                null,
                Map.of("X-Client-Type", "web", "Origin", "http://localhost:5173")
        );

        assertEquals(401, response.statusCode());
        assertEquals(0, validateCalls.get());
        assertEquals(0, blockCalls.get());
    }

    @Test
    void documentsWithApiClientTypeAndCookieOnlyReturnsUnauthorized() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        startUpstreams(validateCalls, "user-123", blockCalls, null, null, null, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest(
                "/v1/documents/doc-1",
                null,
                "ACCESS_TOKEN=" + jwt("{\"sub\":\"user-123\",\"exp\":4102444800}") + "; Path=/; HttpOnly",
                Map.of("X-Client-Type", "api")
        );

        assertEquals(401, response.statusCode());
        assertEquals(0, validateCalls.get());
        assertEquals(0, blockCalls.get());
    }

    @Test
    void authMeForwardsCookieToAuthService() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicReference<String> cookieSeenByAuthMe = new AtomicReference<>();
        startUpstreams(validateCalls, "user-123", blockCalls, null, null, exchange -> {
            cookieSeenByAuthMe.set(exchange.getRequestHeaders().getFirst("Cookie"));
            writeJson(exchange, 200, "{\"userId\":\"user-123\",\"email\":\"user@example.com\",\"name\":\"User\",\"avatarUrl\":\"\",\"roles\":[\"USER\"]}");
        }, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest("/v1/auth/me", null, "sso_session=session-123; ACCESS_TOKEN=access-123");

        assertEquals(200, response.statusCode());
        assertEquals(0, validateCalls.get());
        assertEquals(0, blockCalls.get());
        assertNotNull(cookieSeenByAuthMe.get());
        assertTrue(cookieSeenByAuthMe.get().contains("sso_session=session-123"));
        assertTrue(cookieSeenByAuthMe.get().contains("ACCESS_TOKEN=access-123"));
    }

    @Test
    void authMeForwardsBearerAuthorizationToAuthService() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicReference<String> authHeaderSeenByAuthMe = new AtomicReference<>();
        startUpstreams(validateCalls, "user-123", blockCalls, null, null, exchange -> {
            authHeaderSeenByAuthMe.set(exchange.getRequestHeaders().getFirst("Authorization"));
            writeJson(exchange, 200, "{\"userId\":\"user-123\",\"status\":\"A\"}");
        }, null);
        startGateway();

        String authorizationHeader = "Bearer caller-token";
        HttpResponse<String> response = sendGatewayRequest("/v1/auth/me", authorizationHeader, null);

        assertEquals(200, response.statusCode());
        assertEquals(0, validateCalls.get());
        assertEquals(0, blockCalls.get());
        assertEquals(authorizationHeader, authHeaderSeenByAuthMe.get());
    }

    @Test
    void publicAuthRouteWithoutChannelHintsForwardsWithoutChannelResolution() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicInteger authMeCalls = new AtomicInteger();
        startUpstreams(validateCalls, "user-123", blockCalls, null, null, exchange -> {
            authMeCalls.incrementAndGet();
            writeJson(exchange, 200, "{\"userId\":\"user-123\",\"status\":\"A\"}");
        }, null);
        startGateway();

        String rawResponse = sendRawGatewayRequest("""
                GET /v1/auth/me HTTP/1.1\r
                Host: 127.0.0.1\r
                Connection: close\r
                \r
                """);

        assertTrue(rawResponse.startsWith("HTTP/1.1 200 "), rawResponse);
        assertEquals(0, validateCalls.get());
        assertEquals(0, blockCalls.get());
        assertEquals(1, authMeCalls.get());
    }

    @Test
    void adminRouteChecksPermissionServiceBeforeForwarding() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicInteger permissionCalls = new AtomicInteger();
        AtomicReference<String> permissionMethod = new AtomicReference<>();
        AtomicReference<String> permissionPath = new AtomicReference<>();
        AtomicReference<String> blockPath = new AtomicReference<>();

        startPermissionServer(exchange -> {
            permissionCalls.incrementAndGet();
            permissionMethod.set(exchange.getRequestHeaders().getFirst("X-Original-Method"));
            permissionPath.set(exchange.getRequestHeaders().getFirst("X-Original-Path"));
            writeJson(exchange, 200, "{\"allowed\":true}");
        });
        startUpstreams(validateCalls, "admin-123", blockCalls, exchange -> {
            blockPath.set(exchange.getRequestURI().getPath());
            writeJson(exchange, 200, "{\"ok\":true}");
        }, exchange -> writeJson(
                exchange,
                200,
                "{\"authenticated\":true,\"userId\":\"admin-123\",\"role\":\"ADMIN\",\"status\":\"A\",\"sessionId\":\"session-admin\"}"
        ), null, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest(
                "/v1/admin/dashboard",
                null,
                "sso_session=session-admin; Path=/; HttpOnly",
                Map.of("Origin", "http://localhost:5173")
        );

        assertEquals(200, response.statusCode());
        assertEquals(1, validateCalls.get());
        assertEquals(1, permissionCalls.get());
        assertEquals(1, blockCalls.get());
        assertEquals("GET", permissionMethod.get());
        assertEquals("/v1/admin/dashboard", permissionPath.get());
        assertEquals("/admin/dashboard", blockPath.get());
    }

    @Test
    void adminRouteDeniedWhenPermissionServiceRejects() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicInteger permissionCalls = new AtomicInteger();

        startPermissionServer(exchange -> {
            permissionCalls.incrementAndGet();
            exchange.sendResponseHeaders(403, -1);
            exchange.close();
        });
        startUpstreams(validateCalls, "admin-123", blockCalls, exchange -> {
            writeJson(exchange, 200, "{\"ok\":true}");
        }, exchange -> writeJson(
                exchange,
                200,
                "{\"authenticated\":true,\"userId\":\"admin-123\",\"role\":\"ADMIN\",\"status\":\"A\",\"sessionId\":\"session-admin\"}"
        ), null, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest(
                "/v1/admin/dashboard",
                null,
                "sso_session=session-admin; Path=/; HttpOnly",
                Map.of("Origin", "http://localhost:5173")
        );

        assertEquals(403, response.statusCode());
        assertEquals(1, validateCalls.get());
        assertEquals(1, permissionCalls.get());
        assertEquals(0, blockCalls.get());
    }

    @Test
    void internalPathWithoutInternalSecretReturnsForbidden() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        startUpstreams(validateCalls, "user-123", blockCalls, null, null, null, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest("/v1/internal/ping", null, null);

        assertEquals(403, response.statusCode());
    }

    @Test
    void internalPathWithInternalSecretForwards() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        startUpstreams(validateCalls, "user-123", blockCalls, null, null, null, null);
        startGateway();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + gatewayServer.getAddress().getPort() + "/v1/internal/ping"))
                .timeout(Duration.ofSeconds(3))
                .header("X-Internal-Request-Secret", "dev-internal-jwt-secret")
                .GET()
                .build();

        HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode());
    }

    @Test
    void legacyAuthSsoStartPathWithoutV1PrefixIsAccepted() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicReference<String> requestUriSeenByAuth = new AtomicReference<>();
        startUpstreams(validateCalls, "user-123", blockCalls, null, null, null, exchange -> {
            requestUriSeenByAuth.set(exchange.getRequestURI().toString());
            exchange.getResponseHeaders().add("Location", "http://localhost:5173/auth/callback?code=test");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        startGateway();

        HttpResponse<String> response = sendGatewayRequest("/auth/sso/start?page=editor&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fauth%2Fcallback", null, null);

        assertEquals(302, response.statusCode());
        assertEquals("/auth/sso/start?page=editor&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fauth%2Fcallback", requestUriSeenByAuth.get());
    }

    private void startUpstreams(
            AtomicInteger validateCalls,
            String validatedUserId,
            AtomicInteger blockCalls,
            HttpHandler blockHandler,
            HttpHandler authValidateHandler,
            HttpHandler authMeHandler,
            HttpHandler authSsoStartHandler
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
        userServer.createContext("/", exchange -> writeJson(exchange, 200, "{\"ok\":true}"));
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
        blockServer.createContext("/workspaces", blockEntry);
        blockServer.createContext("/editor-operations", blockEntry);
        blockServer.createContext("/admin", blockEntry);
        blockServer.start();
    }

    private void startGateway() throws IOException {
        Map<String, String> env = new HashMap<>();
        env.put("GATEWAY_BIND", "127.0.0.1");
        env.put("GATEWAY_PORT", "0");
        env.put("GATEWAY_INTERNAL_IP_GUARD_ENABLED", "false");
        env.put("GATEWAY_IP_GUARD_ENABLED", "false");
        env.put("GATEWAY_PERMISSION_CACHE_ENABLED", "false");
        env.put("AUTH_JWT_VERIFY_ENABLED", "false");
        env.put("AUTH_SERVICE_URL", "http://127.0.0.1:" + authServer.getAddress().getPort());
        env.put("USER_SERVICE_URL", "http://127.0.0.1:" + userServer.getAddress().getPort());
        env.put("BLOCK_SERVICE_URL", "http://127.0.0.1:" + blockServer.getAddress().getPort());
        if (permissionServer != null) {
            String permissionBase = "http://127.0.0.1:" + permissionServer.getAddress().getPort();
            env.put("PERMISSION_SERVICE_URL", permissionBase);
            env.put("PERMISSION_ADMIN_VERIFY_URL", permissionBase + "/permissions/internal/admin/verify");
        }
        GatewayConfig config = GatewayConfig.fromEnv(env);
        gatewayServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        gatewayServer.createContext("/", new GatewayHandler(config));
        gatewayServer.start();
    }

    private void startPermissionServer(HttpHandler permissionHandler) throws IOException {
        permissionServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        permissionServer.createContext("/permissions/internal/admin/verify", exchange -> {
            if (permissionHandler != null) {
                permissionHandler.handle(exchange);
                return;
            }
            writeJson(exchange, 200, "{\"allowed\":true}");
        });
        permissionServer.start();
    }

    private HttpResponse<String> sendGatewayRequest(String path, String authorizationHeader, String cookieHeader) throws Exception {
        return sendGatewayRequest(path, authorizationHeader, cookieHeader, Map.of());
    }

    private HttpResponse<String> sendGatewayRequest(String path, String authorizationHeader, String cookieHeader, Map<String, String> extraHeaders) throws Exception {
        assertNotNull(gatewayServer);
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + gatewayServer.getAddress().getPort() + path))
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

    private String sendRawGatewayRequest(String rawRequest) throws IOException {
        assertNotNull(gatewayServer);
        try (Socket socket = new Socket("127.0.0.1", gatewayServer.getAddress().getPort())) {
            socket.setSoTimeout(3000);
            socket.getOutputStream().write(rawRequest.getBytes(StandardCharsets.UTF_8));
            socket.getOutputStream().flush();
            return new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        }
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
