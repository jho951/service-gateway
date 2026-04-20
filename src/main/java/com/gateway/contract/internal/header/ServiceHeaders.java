package com.gateway.contract.internal.header;

/**
 * Gateway와 내부 서비스 간 통신에 사용하는 커스텀 헤더
 * <p>
 * 외부 클라이언트가 동일한 헤더를 보내더라도 신뢰하면 안 되며,
 * gateway가 인증/검증 후 제거 후 재구성해서 내부 서비스에만 전달해야 합니다.
 * </p>
 */
public final class ServiceHeaders {
    private ServiceHeaders() {}

    /** 인증 완료 후 gateway가 내부 서비스에 전달하는 신뢰 헤더입니다. */
    public static final class Trusted {
        private Trusted() {}

        /** 로그인한 사용자의 고유 식별자(ID) */
        public static final String USER_ID = "X-User-Id";
        /** 사용자의 권한 */
        public static final String USER_ROLE = "X-User-Role";
        /** 통합 로그인(SSO) 환경에서 사용하는 인증 토큰 */
        public static final String SESSION_ID = "X-Session-Id";

        /** 클라이언트 유형(web, mobile, desktop 등) */
        public static final String CLIENT_TYPE = "X-Client-Type";
    }

    /** 원본 요청 정보를 내부 서비스에 전달할 때 사용하는 헤더입니다. */
    public static final class Forwarded {
        private Forwarded() {}

        /** 클라이언트가 처음에 보낸 HTTP 메서드 */
        public static final String ORIGINAL_METHOD = "X-Original-Method";
        /** 클라이언트가 실제로 호출한 원본 주소 */
        public static final String ORIGINAL_URI = "X-Original-Uri";
        /** 프록시나 게이트웨이를 거치기 전, 사용자의 실제 접속 IP 주소 */
        public static final String ORIGINAL_PATH = "X-Original-Path";
        /** 클라이언트 실제 접속 IP */
        public static final String CLIENT_IP = "X-Client-Ip";
    }

    /** 인증 교환 흐름에서만 사용하는 auth 전용 헤더입니다. */
    public static final class Auth {
        private Auth() {}

        /** SSO 인증 교환에 사용하는 일회성 티켓 */
        public static final String SSO_TICKET = "X-SSO-Ticket";

        /** INTERNAL 경로 호출을 허용하는 내부 전용 공유 시크릿 */
        public static final String INTERNAL_REQUEST_SECRET = "X-Internal-Request-Secret";
    }
}
