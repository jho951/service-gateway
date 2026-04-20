package com.gateway.routing;

import java.net.URI;
import java.util.List;

/** 요청 경로를 정책 라우트와 업스트림 URI로 해석합니다. */
public final class RouteResolver {
    private final List<RouteDefinition> routes;

    /**
     * 생성자
     * @param routes 우선순위 정렬이 끝난 라우트 목록
     */
    public RouteResolver(List<RouteDefinition> routes) {
        this.routes = routes;
    }

    /**
     * 요청 경로와 쿼리 해석
     * @param requestPath 요청 경로
     * @param query 원본 쿼리 문자열
     * @return 매칭 결과, 없으면 {@code null}
     */
    public RouteMatch resolve(String requestPath, String query) {
        return routes.stream()
                .filter(route -> route.matches(requestPath))
                .findFirst()
                .map(route -> new RouteMatch(route, rewriteUri(route.targetBaseUri(), route.rewritePath(requestPath), query)))
                .orElse(null);
    }

    private URI rewriteUri(URI baseUri, String requestPath, String query) {
        String basePath = baseUri.getPath() == null ? "" : baseUri.getPath();
        String combinedPath = combinePaths(basePath, requestPath);
        return URI.create(baseUri.getScheme()
                + "://"
                + baseUri.getAuthority()
                + combinedPath
                + (query == null || query.isBlank() ? "" : "?" + query));
    }

    private String combinePaths(String basePath, String requestPath) {
        String normalizedBase = (basePath == null || basePath.isBlank()) ? "" : basePath;
        if (normalizedBase.endsWith("/")) normalizedBase = normalizedBase.substring(0, normalizedBase.length() - 1);
        return normalizedBase + requestPath;
    }
}
