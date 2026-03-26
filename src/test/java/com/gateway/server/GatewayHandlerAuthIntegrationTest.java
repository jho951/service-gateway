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
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
    void usersMeWithoutTokenReturnsUnauthorized() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger userCalls = new AtomicInteger();
        startUpstreams(validateCalls, null, userCalls, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest("/api/users/me", null);

        assertEquals(401, response.statusCode());
        assertEquals(0, validateCalls.get());
        assertEquals(0, userCalls.get());
    }

    @Test
    void usersMeWithInvalidTokenReturnsUnauthorized() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger userCalls = new AtomicInteger();
        startUpstreams(validateCalls, null, userCalls, null);
        startGateway();

        HttpResponse<String> response = sendGatewayRequest("/api/users/me", "Bearer not-a-jwt");

        assertEquals(401, response.statusCode());
        assertEquals(0, validateCalls.get());
        assertEquals(0, userCalls.get());
    }

    @Test
    void usersMeWithValidTokenValidatesWithAuthAndForwardsAuthorizationHeader() throws Exception {
        AtomicInteger validateCalls = new AtomicInteger();
        AtomicInteger userCalls = new AtomicInteger();
        AtomicReference<String> authHeaderSeenByUser = new AtomicReference<>();
        AtomicReference<String> userIdHeaderSeenByUser = new AtomicReference<>();
        startUpstreams(validateCalls, "user-123", userCalls, exchange -> {
            authHeaderSeenByUser.set(exchange.getRequestHeaders().getFirst("Authorization"));
            userIdHeaderSeenByUser.set(exchange.getRequestHeaders().getFirst("X-User-Id"));
            writeJson(exchange, 200, "{\"ok\":true}");
        });
        startGateway();

        String validShapeToken = "Bearer " + jwt("{\"sub\":\"user-123\"}");
        HttpResponse<String> response = sendGatewayRequest("/api/users/me", validShapeToken);

        assertEquals(200, response.statusCode());
        assertEquals(1, validateCalls.get());
        assertEquals(1, userCalls.get());
        assertEquals(validShapeToken, authHeaderSeenByUser.get());
        assertEquals("user-123", userIdHeaderSeenByUser.get());
    }

    private void startUpstreams(
            AtomicInteger validateCalls,
            String validatedUserId,
            AtomicInteger userCalls,
            HttpHandler usersHandler
    ) throws IOException {
        authServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        authServer.createContext("/auth/internal/session/validate", exchange -> {
            validateCalls.incrementAndGet();
            if (validatedUserId == null) {
                writeJson(exchange, 401, "{\"authenticated\":false}");
                return;
            }
            writeJson(exchange, 200, "{\"authenticated\":true,\"userId\":\"" + validatedUserId + "\"}");
        });
        authServer.start();

        userServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        userServer.createContext("/api/users/me", exchange -> {
            userCalls.incrementAndGet();
            if (usersHandler != null) {
                usersHandler.handle(exchange);
                return;
            }
            writeJson(exchange, 200, "{\"ok\":true}");
        });
        userServer.start();

        blockServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        blockServer.createContext("/", exchange -> writeJson(exchange, 200, "{\"ok\":true}"));
        blockServer.start();
    }

    private void startGateway() throws IOException {
        Map<String, String> env = Map.of(
                "GATEWAY_BIND", "127.0.0.1",
                "GATEWAY_PORT", "0",
                "GATEWAY_INTERNAL_IP_GUARD_ENABLED", "false",
                "GATEWAY_IP_GUARD_ENABLED", "false",
                "AUTH_SERVICE_URL", "http://127.0.0.1:" + authServer.getAddress().getPort(),
                "USER_SERVICE_URL", "http://127.0.0.1:" + userServer.getAddress().getPort(),
                "BLOCK_SERVICE_URL", "http://127.0.0.1:" + blockServer.getAddress().getPort()
        );
        GatewayConfig config = GatewayConfig.fromEnv(env);
        gatewayServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        gatewayServer.createContext("/", new GatewayHandler(config));
        gatewayServer.start();
    }

    private HttpResponse<String> sendGatewayRequest(String path, String authorizationHeader) throws Exception {
        assertNotNull(gatewayServer);
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + gatewayServer.getAddress().getPort() + path))
                .timeout(Duration.ofSeconds(3))
                .GET();
        if (authorizationHeader != null) {
            requestBuilder.header("Authorization", authorizationHeader);
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
