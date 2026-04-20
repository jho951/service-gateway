package com.gateway.auth;

import com.gateway.contract.internal.header.ServiceHeaders;
import com.gateway.contract.internal.header.TraceHeaders;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/** 관리자 경로에 대한 추가 권한 확인을 Permission Service에 위임합니다. */
public final class PermissionServiceClient {
    private final HttpClient client;
    private final Duration timeout;

    public PermissionServiceClient(Duration timeout) {
        this.client = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        this.timeout = timeout;
    }

    public boolean verifyAdminAccess(
            URI verifyUri,
            String method,
            String path,
            String requestId,
            String correlationId,
            AuthResult authResult,
            String internalRequestSecret
    ) throws IOException, InterruptedException {
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(verifyUri)
                .timeout(timeout)
                .POST(HttpRequest.BodyPublishers.noBody())
                .header(ServiceHeaders.Forwarded.ORIGINAL_METHOD, method)
                .header(ServiceHeaders.Forwarded.ORIGINAL_PATH, path)
                .header(TraceHeaders.REQUEST_ID, requestId)
                .header(TraceHeaders.CORRELATION_ID, correlationId)
                .header(ServiceHeaders.Trusted.USER_ID, authResult.getUserId())
                .header(ServiceHeaders.Trusted.SESSION_ID, authResult.getSessionId());

        if (internalRequestSecret != null && !internalRequestSecret.isBlank()) {
            requestBuilder.header(ServiceHeaders.Auth.INTERNAL_REQUEST_SECRET, internalRequestSecret);
        }

        HttpRequest request = requestBuilder.build();

        HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
        return response.statusCode() == 200;
    }
}
