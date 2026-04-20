package com.gateway.proxy;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 게이트웨이에서 업스트림 서비스로 요청을 전달하는 HTTP 프록시 클라이언트입니다.
 *<p>
 * hop-by-hop 헤더는 제거하고,
 * {@code X-Forwarded-*} 헤더를 재구성합니다.
 *</p>
 */
public final class ReverseProxyClient {
    private static final Set<String> HOP_BY_HOP_HEADERS = Set.of(
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "host",
            "content-length"
    );

    private final HttpClient client;
    private final Duration timeout;

    /**
     * @param timeout 연결 및 요청에 사용할 타임아웃
     */
    public ReverseProxyClient(Duration timeout) {
        this.client = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        this.timeout = timeout;
    }

    /**
     * 업스트림 대상 서비스로 요청을 전달합니다.
     *
     * @param request 프록시 요청 모델
     * @return 업스트림 응답
     * @throws IOException 네트워크 또는 입출력 오류 발생 시 전달됩니다
     * @throws InterruptedException 현재 스레드가 인터럽트되면 전달됩니다
     */
    public ProxyResponse forward(ProxyRequest request) throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(request.getTargetUri())
                .timeout(timeout)
                .method(request.getMethod(), bodyPublisher(request.getBody()));

        request.getHeaders().forEach((name, values) -> {
            if (isForwardable(name) && !isManagedForwardedHeader(name)) {
                for (String value : values) {
                    builder.header(name, value);
                }
            }
        });

        builder.setHeader("X-Forwarded-For", resolveForwardedFor(request));
        builder.setHeader("X-Forwarded-Proto", resolveForwardedProto(request));
        builder.setHeader("X-Forwarded-Host", resolveForwardedHost(request));
        builder.setHeader("X-Forwarded-Port", resolveForwardedPort(request));

        try {
            HttpResponse<byte[]> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
            return new ProxyResponse(response.statusCode(), filterResponseHeaders(response.headers().map()), response.body());
        } catch (IOException ex) {
            throw new IOException(
                    "Upstream request failed: method=" + request.getMethod()
                            + " targetUri=" + request.getTargetUri()
                            + " reason=" + ex.getMessage(),
                    ex
            );
        }
    }

    /**
     * 요청 바디 유무에 맞춰 적절한 BodyPublisher 를 선택합니다.
     *
     * @param body 요청 바디
     * @return 비어 있거나 바이트 배열 기반의 publisher
     */
    private static HttpRequest.BodyPublisher bodyPublisher(byte[] body) {
        return body.length == 0
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(body);
    }

    /**
     * @param headerName 검사할 헤더 이름
     * @return 프록시 전달 가능한 헤더이면 {@code true}
     */
    private static boolean isForwardable(String headerName) {
        return !HOP_BY_HOP_HEADERS.contains(headerName.toLowerCase());
    }

    private static boolean isManagedForwardedHeader(String headerName) {
        String normalized = headerName.toLowerCase();
        return "x-forwarded-for".equals(normalized)
                || "x-forwarded-proto".equals(normalized)
                || "x-forwarded-host".equals(normalized)
                || "x-forwarded-port".equals(normalized);
    }

    private static String resolveForwardedFor(ProxyRequest request) {
        String existing = firstHeaderValue(request.getHeaders(), "X-Forwarded-For");
        if (existing == null || existing.isBlank()) return request.getClientIp();
        return existing;
    }

    private static String resolveForwardedProto(ProxyRequest request) {
        String existing = firstHeaderValue(request.getHeaders(), "X-Forwarded-Proto");
        if (existing == null || existing.isBlank()) return request.getTargetUri().getScheme();
        return existing;
    }

    private static String resolveForwardedHost(ProxyRequest request) {
        String existing = firstHeaderValue(request.getHeaders(), "X-Forwarded-Host");
        if (existing != null && !existing.isBlank()) return existing;

        String host = firstHeaderValue(request.getHeaders(), "Host");
        if (host == null || host.isBlank()) return request.getTargetUri().getHost();

        int separatorIndex = host.lastIndexOf(':');
        if (separatorIndex > 0 && host.indexOf(']') < separatorIndex) return host.substring(0, separatorIndex);
        return host;
    }

    private static String resolveForwardedPort(ProxyRequest request) {
        String existing = firstHeaderValue(request.getHeaders(), "X-Forwarded-Port");
        if (existing != null && !existing.isBlank()) return existing;

        String host = firstHeaderValue(request.getHeaders(), "Host");
        if (host != null && !host.isBlank()) {
            int separatorIndex = host.lastIndexOf(':');
            if (separatorIndex > 0 && separatorIndex < host.length() - 1 && host.indexOf(']') < separatorIndex) return host.substring(separatorIndex + 1);
        }

        String proto = resolveForwardedProto(request);
        return "https".equalsIgnoreCase(proto) ? "443" : "80";
    }

    private static String firstHeaderValue(Map<String, List<String>> headers, String headerName) {
        return headers.entrySet().stream()
                .filter(entry -> headerName.equalsIgnoreCase(entry.getKey()))
                .findFirst()
                .map(Map.Entry::getValue)
                .filter(values -> !values.isEmpty())
                .map(values -> values.get(0))
                .orElse(null);
    }

    /**
     * 업스트림 응답 헤더 중 hop-by-hop 헤더를 제거합니다.
     *
     * @param headers 업스트림 응답 헤더
     * @return 전달 가능한 응답 헤더 맵
     */
    private static Map<String, List<String>> filterResponseHeaders(Map<String, List<String>> headers) {
        return headers.entrySet().stream()
                .filter(entry -> isForwardable(entry.getKey()))
                .collect(java.util.stream.Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }
}
