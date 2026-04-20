package com.gateway.code;

/** Gateway가 클라이언트에 반환하는 표준 에러 코드 집합입니다. */
public enum GatewayErrorCode {
    INVALID_REQUEST(400, "1000", "요청 형식 또는 파라미터가 잘못된 경우"),
    INVALID_REQUEST_CHANNEL(400, "1001", "요청 채널을 판정할 수 없는 경우"),
    INVALID_CLIENT_TYPE(400, "1002", "지원하지 않는 클라이언트 타입인 경우"),
    MISSING_AUTH_CREDENTIALS(401, "1003", "인증 정보가 없거나 현재 채널에서 쓸 수 있는 인증 수단이 없는 경우"),
    AUTH_CHANNEL_MISMATCH(401, "1004", "클라이언트 채널과 인증 수단이 일치하지 않는 경우"),
    UNAUTHORIZED(401, "1005", "인증 시도는 했지만 검증에 실패한 경우"),
    FORBIDDEN(403, "1006", "접근이 허용되지 않는 경우"),
    NOT_FOUND(404, "1007", "요청한 경로를 찾을 수 없는 경우"),
    METHOD_NOT_ALLOWED(405, "1008", "허용되지 않은 HTTP 메서드인 경우"),
    PAYLOAD_TOO_LARGE(413, "1009", "요청 본문이 허용 크기를 초과한 경우"),
    TOO_MANY_REQUESTS(429, "1010", "요청이 너무 많은 경우"),
    INTERNAL_ERROR(500, "1011", "게이트웨이 처리 중 오류가 발생한 경우"),
    UPSTREAM_FAILURE(502, "1012", "업스트림 호출에 실패한 경우"),
    UPSTREAM_TIMEOUT(504, "1013", "업스트림 응답 시간이 초과된 경우");

    private final int httpStatus;
    private final String code;
    private final String message;

    /**
     * 생성자
     * @param httpStatus http 상태코드
     * @param code 커스텀 상태코드 (전용 1000 ~ 1999)
     * @param message 추가 메시지
     */
    GatewayErrorCode(int httpStatus, String code, String message) {
        this.httpStatus = httpStatus;
        this.code = code;
        this.message = message;
    }

    public int getHttpStatus() {return httpStatus;}
    public String getCode() {return code;}
    public String getMessage() {return message;}
}
