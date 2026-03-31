package com.gateway.routing;

import java.net.URI;
import java.util.Comparator;
import java.util.Objects;

/** 라우트 정의와 경로 변환 기능 */
public final class RouteDefinition {
    private final String pathPattern;
    private final RouteType routeType;
    private final String upstreamName;
    private final URI targetBaseUri;
    private final String stripPrefix;

    /** 패턴 길이가 긴, 더 구체적인 라우트가 먼저 매칭되도록 정렬합니다. */
    public static final Comparator<RouteDefinition> MOST_SPECIFIC_FIRST =
            Comparator.comparingInt((RouteDefinition route) -> route.pathPattern().length()).reversed();

    /**
     * 다른 생성자를 호출
     * stripPrefix는 빈 값입니다.
     */
    public RouteDefinition(String pathPattern, RouteType routeType, String upstreamName, URI targetBaseUri) {
        this(pathPattern, routeType, upstreamName, targetBaseUri, "");
    }

    /**
     * 생성자
     * @param pathPattern Gateway가 받는 URL {@code /v1/auth/**}
     * @param routeType 공개/보호/관리자/내부 경로 구분
     * @param upstreamName 로깅과 운영 식별용 업스트림 이름
     * @param targetBaseUri 업스트림 서비스 기본 URI
     * @param stripPrefix 업스트림에 전달하기 전에 제거할 외부 공통 prefix
     */
    public RouteDefinition(
            String pathPattern,
            RouteType routeType,
            String upstreamName,
            URI targetBaseUri,
            String stripPrefix
    ) {
        this.pathPattern = pathPattern;
        this.routeType = routeType;
        this.upstreamName = upstreamName;
        this.targetBaseUri = targetBaseUri;
        this.stripPrefix = stripPrefix;
    }

    public String pathPattern() {return pathPattern;}
    public RouteType routeType() {return routeType;}
    public String upstreamName() {return upstreamName;}
    public URI targetBaseUri() {return targetBaseUri;}
    public String stripPrefix() {return stripPrefix;}

    /**
     * 와일드카드 패턴 경로 검사
     * @param requestPath 요청 경로
     * @return 일치하면 {@code true}
     */
    public boolean matches(String requestPath) {
        if (pathPattern.endsWith("/**")) {
            String prefix = pathPattern.substring(0, pathPattern.length() - 3);
            return requestPath.equals(prefix) || requestPath.startsWith(prefix + "/");
        }
        return requestPath.equals(pathPattern);
    }

    /**
     * 외부 경로에서 stripPrefix(/v1)를 잘라냅니다.
     * @param requestPath 외부 경로
     * @return stripPrefix(/v1)를 잘라낸 경로
     */
    public String rewritePath(String requestPath) {
        if (stripPrefix == null) return requestPath;
        if (stripPrefix.isBlank()) return requestPath;
        if (!requestPath.startsWith(stripPrefix)) return requestPath;

        String rewrittenPath = requestPath.substring(stripPrefix.length());
        if (rewrittenPath.isBlank()) return "/";
        return rewrittenPath;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RouteDefinition that)) return false;
        return Objects.equals(pathPattern, that.pathPattern)
                && routeType == that.routeType
                && Objects.equals(upstreamName, that.upstreamName)
                && Objects.equals(targetBaseUri, that.targetBaseUri)
                && Objects.equals(stripPrefix, that.stripPrefix);
    }

    @Override
    public int hashCode() {
        return Objects.hash(pathPattern, routeType, upstreamName, targetBaseUri, stripPrefix);
    }

    @Override
    public String toString() {
        return "RouteDefinition{"
                + "pathPattern='" + pathPattern + '\''
                + ", routeType=" + routeType
                + ", upstreamName='" + upstreamName + '\''
                + ", targetBaseUri=" + targetBaseUri
                + ", stripPrefix='" + stripPrefix + '\''
                + '}';
    }
}
