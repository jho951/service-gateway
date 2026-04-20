package com.gateway.exception;

import com.gateway.code.GatewayErrorCode;
import com.gateway.http.Jsons;

/** Gateway 예외를 HTTP 응답 바디와 상태 코드로 변환하는 헬퍼입니다. */
public final class GatewayExceptionHandler {
    private GatewayExceptionHandler() {}

    public static ResponseSpec handleGlobalException(GatewayException ex) {
        return handleGatewayException(ex, "", "");
    }

    public static ResponseSpec handleGatewayException(GatewayException ex, String path, String requestId) {
        return fromErrorCode(ex.getErrorCode(), path, requestId);
    }

    public static ResponseSpec handleIllegalArgumentException(IllegalArgumentException ex) {
        return handleIllegalArgumentException(ex, "", "");
    }

    public static ResponseSpec handleIllegalArgumentException(IllegalArgumentException ex, String path, String requestId) {
        return fromErrorCode(GatewayErrorCode.INVALID_REQUEST, path, requestId);
    }

    public static ResponseSpec handleException(java.lang.Exception ex) {
        return handleException(ex, "", "");
    }

    public static ResponseSpec handleException(java.lang.Exception ex, String path, String requestId) {
        return fromErrorCode(GatewayErrorCode.INTERNAL_ERROR, path, requestId);
    }

    public static ResponseSpec fromErrorCode(GatewayErrorCode gatewayErrorCode) {
        return fromErrorCode(gatewayErrorCode, "", "");
    }

    public static ResponseSpec fromErrorCode(GatewayErrorCode gatewayErrorCode, String path, String requestId) {
        String safePath = (path == null || path.isBlank()) ? "/" : path;
        String safeRequestId = (requestId == null || requestId.isBlank()) ? "" : requestId;

        GatewayErrorResponse body = new GatewayErrorResponse(
                gatewayErrorCode.getCode(),
                gatewayErrorCode.getMessage(),
                safePath,
                safeRequestId
        );

        return new ResponseSpec(
                gatewayErrorCode.getHttpStatus(),
                Jsons.toJson(body)
        );
    }
}
