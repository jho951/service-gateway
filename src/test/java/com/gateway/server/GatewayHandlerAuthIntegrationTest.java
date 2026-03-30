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
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GatewayHandlerAuthIntegrationTest {
    private HttpServer authServer;
    private HttpServer userServer;
    private HttpServer blockServer;
    private HttpServer gatewayServer;

    @AfterEach
    void tearDown() {
        stopServer(gatewayServer);
        stopServer(authServer);
        stopServer(userServer);
        stopServer(blockServer);
    }

    @Test
    void documentsWithoutBearerAndCookieReturnsUnauthorized() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        startUpstreams(validateCalls, "user-123", blockCalls, null, null, null);
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
        startUpstreams(validateCalls, "user-123", blockCalls, exchange -> {
            authHeaderSeenByBlock.set(exchange.getRequestHeaders().getFirst("Authorization"));
            userIdHeaderSeenByBlock.set(exchange.getRequestHeaders().getFirst("X-User-Id"));
            writeJson(exchange, 200, "{\"ok\":true}");
        }, null, null);
        startGateway();

        String validShapeToken = "Bearer " + jwt("{\"sub\":\"user-123\",\"exp\":4102444800}");
        HttpResponse<String> response = sendGatewayRequest("/v1/documents/doc-1", validShapeToken, null);

        assertEquals(200, response.statusCode());
        assertEquals(0, validateCalls.get());
        assertEquals(1, blockCalls.get());
        assertNotNull(authHeaderSeenByBlock.get());
        assertTrue(authHeaderSeenByBlock.get().startsWith("Bearer "));
        assertNotEquals(validShapeToken, authHeaderSeenByBlock.get());
        assertEquals("user-123", userIdHeaderSeenByBlock.get());
    }

    @Test
    void documentsWithAccessTokenCookieValidatesAndForwardsInternalJwt() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicReference<String> authHeaderSeenByBlock = new AtomicReference<>();
        startUpstreams(validateCalls, "user-456", blockCalls, exchange -> {
            authHeaderSeenByBlock.set(exchange.getRequestHeaders().getFirst("Authorization"));
            writeJson(exchange, 200, "{\"ok\":true}");
        }, null, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest("/v1/documents/doc-2", null, "ACCESS_TOKEN=" + jwt("{\"sub\":\"user-456\",\"exp\":4102444800}") + "; Path=/; HttpOnly");

        assertEquals(200, response.statusCode());
        assertEquals(0, validateCalls.get());
        assertEquals(1, blockCalls.get());
        assertNotNull(authHeaderSeenByBlock.get());
        assertTrue(authHeaderSeenByBlock.get().startsWith("Bearer "));
    }

    @Test
    void documentsWithSsoSessionCookieValidatesAndForwardsInternalJwt() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicReference<String> authHeaderSeenByBlock = new AtomicReference<>();
        AtomicReference<String> cookieSeenByValidate = new AtomicReference<>();
        startUpstreams(validateCalls, "user-789", blockCalls, exchange -> {
            authHeaderSeenByBlock.set(exchange.getRequestHeaders().getFirst("Authorization"));
            writeJson(exchange, 200, "{\"ok\":true}");
        }, exchange -> {
            cookieSeenByValidate.set(exchange.getRequestHeaders().getFirst("Cookie"));
            writeJson(exchange, 200, "{\"authenticated\":true,\"userId\":\"user-789\"}");
        }, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest("/v1/documents/doc-3", null, "sso_session=session-789; Path=/; HttpOnly");

        assertEquals(200, response.statusCode());
        assertEquals(1, validateCalls.get());
        assertEquals(1, blockCalls.get());
        assertNotNull(authHeaderSeenByBlock.get());
        assertTrue(authHeaderSeenByBlock.get().startsWith("Bearer "));
        assertNotNull(cookieSeenByValidate.get());
        assertTrue(cookieSeenByValidate.get().contains("sso_session=session-789"));
    }

    @Test
    void authMeForwardsCookieToAuthService() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        AtomicReference<String> cookieSeenByAuthMe = new AtomicReference<>();
        startUpstreams(validateCalls, "user-123", blockCalls, null, null, exchange -> {
            cookieSeenByAuthMe.set(exchange.getRequestHeaders().getFirst("Cookie"));
            writeJson(exchange, 200, "{\"userId\":\"user-123\",\"email\":\"user@example.com\",\"name\":\"User\",\"avatarUrl\":\"\",\"roles\":[\"USER\"]}");
        });
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
    void internalPathWithoutInternalSecretReturnsForbidden() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        startUpstreams(validateCalls, "user-123", blockCalls, null, null, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest("/v1/internal/ping", null, null);

        assertEquals(403, response.statusCode());
    }

    @Test
    void internalPathWithInternalSecretForwards() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger blockCalls = new AtomicInteger();
        startUpstreams(validateCalls, "user-123", blockCalls, null, null, null);
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

    private void startUpstreams(
            AtomicInteger validateCalls,
            String validatedUserId,
            AtomicInteger blockCalls,
            HttpHandler blockHandler,
            HttpHandler authValidateHandler,
            HttpHandler authMeHandler
    ) throws IOException {
        authServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        authServer.createContext("/auth/internal/session/validate", exchange -> {
            validateCalls.incrementAndGet();
            if (authValidateHandler != null) {
                authValidateHandler.handle(exchange);
            }
            if (validatedUserId == null) {
                writeJson(exchange, 401, "{\"authenticated\":false}");
                return;
            }
            writeJson(exchange, 200, "{\"authenticated\":true,\"userId\":\"" + validatedUserId + "\"}");
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
            writeJson(exchange, 200, "{\"userId\":\"" + validatedUserId + "\"}");
        });
        authServer.createContext("/internal/ping", exchange -> writeJson(exchange, 200, "{\"ok\":true}"));
        authServer.start();

        userServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        userServer.createContext("/", exchange -> writeJson(exchange, 200, "{\"ok\":true}"));
        userServer.start();

        blockServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        blockServer.createContext("/documents", exchange -> {
            blockCalls.incrementAndGet();
            if (blockHandler != null) {
                blockHandler.handle(exchange);
                return;
            }
            writeJson(exchange, 200, "{\"ok\":true}");
        });
        blockServer.start();
    }

    private void startGateway() throws IOException {
        Map<String, String> env = Map.of(
                "GATEWAY_BIND", "127.0.0.1",
                "GATEWAY_PORT", "0",
                "GATEWAY_INTERNAL_IP_GUARD_ENABLED", "false",
                "GATEWAY_IP_GUARD_ENABLED", "false",
                "AUTH_JWT_VERIFY_ENABLED", "false",
                "AUTH_SERVICE_URL", "http://127.0.0.1:" + authServer.getAddress().getPort(),
                "USER_SERVICE_URL", "http://127.0.0.1:" + userServer.getAddress().getPort(),
                "BLOCK_SERVICE_URL", "http://127.0.0.1:" + blockServer.getAddress().getPort()
        );
        GatewayConfig config = GatewayConfig.fromEnv(env);
        gatewayServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        gatewayServer.createContext("/", new GatewayHandler(config));
        gatewayServer.start();
    }

    private HttpResponse<String> sendGatewayRequest(String path, String authorizationHeader, String cookieHeader) throws Exception {
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
        return HttpClient.newHttpClient().send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
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
}
