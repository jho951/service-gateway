package com.gateway.contract;

import com.gateway.contract.internal.header.ServiceHeaders;
import com.gateway.contract.internal.header.TraceHeaders;

/**
 * 게이트웨이와 내부 서비스 사이에서 쓰는 공통 API 계약 정의입니다.
 */
public final class InternalServiceApi {
    private InternalServiceApi() {}

    public static final class Headers {
        private Headers() {}

        public static final String USER_ID = ServiceHeaders.Trusted.USER_ID;
        public static final String USER_ROLE = ServiceHeaders.Trusted.USER_ROLE;
        public static final String USER_STATUS = ServiceHeaders.Trusted.USER_STATUS;
        public static final String SESSION_ID = ServiceHeaders.Trusted.SESSION_ID;

        public static final String REQUEST_ID = TraceHeaders.REQUEST_ID;
        public static final String CORRELATION_ID = TraceHeaders.CORRELATION_ID;

        public static final String ORIGINAL_METHOD = ServiceHeaders.Forwarded.ORIGINAL_METHOD;
        public static final String ORIGINAL_PATH = ServiceHeaders.Forwarded.ORIGINAL_PATH;

        public static final String CLIENT_TYPE = ServiceHeaders.Trusted.CLIENT_TYPE;
    }
}
