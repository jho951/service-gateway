package com.gateway.contract.internal.path;

/** 내부 서비스 API 경로 */
public final class ServicePaths {
    private ServicePaths() {}

    /** auth-service 내부 경로 */
    public static final class Auth {
        private Auth() {}
        /** 사용자 자격 증명으로 표준 토큰을 발급 */
        public static final String LOGIN = "/auth/login";
        /** 세션/인증 상태 유효성 검증 */
        public static final String SESSION_VALIDATE = "/auth/internal/session/validate";
    }

    /** permission-service 내부 경로 */
    public static final class Permission {
        private Permission() {}
        /** 관리자 권한 보유 여부 검증 */
        public static final String ADMIN_VERIFY = "/permissions/internal/admin/verify";
    }

    /** block-service downstream 경로 */
    public static final class Block {
        private Block() {}

        /** 문서 리소스 루트 */
        public static final String DOCUMENTS = "/documents";

        /** 워크스페이스 리소스 루트 */
        public static final String WORKSPACES = "/workspaces";

        /** 에디터 작업 리소스 루트 */
        public static final String EDITOR_OPERATIONS = "/editor-operations";

        /** 관리자 리소스 루트 */
        public static final String ADMIN = "/admin";
    }
}
