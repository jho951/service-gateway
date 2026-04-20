package com.gateway.exception;

import com.gateway.code.GatewayErrorCode;

/** Gateway 정책 위반이나 인증 실패를 표현하는 런타임 예외입니다. */
public class GatewayException extends RuntimeException {
    private final GatewayErrorCode gatewayErrorCode;

    /**
     * 생성자
     * @param gatewayErrorCode 에러 코드
     */
    public GatewayException(GatewayErrorCode gatewayErrorCode) {
        super(gatewayErrorCode.getMessage());
        this.gatewayErrorCode = gatewayErrorCode;
    }

    public GatewayErrorCode getErrorCode() {
        return gatewayErrorCode;
    }
}
