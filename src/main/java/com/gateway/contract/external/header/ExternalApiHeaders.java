package com.gateway.contract.external.header;

/** Gateway가 외부 요청에서 읽는 헤더 이름을 정의합니다. */
public final class ExternalApiHeaders {
    private ExternalApiHeaders() {}

    public static final String CLIENT_TYPE = "X-Client-Type";
    public static final String APP_VERSION = "X-App-Version";
    public static final String DEVICE_ID = "X-Device-Id";
    public static final String LOCALE = "X-Locale";
    public static final String REQUEST_ID = "X-Request-Id";
}
