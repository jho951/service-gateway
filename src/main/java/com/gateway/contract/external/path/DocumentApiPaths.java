package com.gateway.contract.external.path;

/** 문서/블록 관련 외부 공개 경로 */
public final class DocumentApiPaths {
    private DocumentApiPaths() {}

    /** 문서 일반 경로 */
    public static final String DOCUMENTS_ALL = "/v1/documents/**";

    /** 워크스페이스 일반 경로 */
    public static final String WORKSPACES_ALL = "/v1/workspaces/**";

    /** 에디터 작업 경로 */
    public static final String EDITOR_OPERATIONS_ALL = "/v1/editor-operations/**";

    /** 관리자/운영용 외부 경로 */
    public static final String ADMIN_ALL = "/v1/admin/**";
}
