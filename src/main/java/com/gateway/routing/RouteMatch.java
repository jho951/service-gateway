package com.gateway.routing;

import java.net.URI;
import java.util.Objects;

/**
 * 특정 요청 경로를 해석
 * @param route 매칭된 라우트 정의
 * @param targetUri 실제 프록시 대상이 되는 최종 URI
 */
public final class RouteMatch {
    private final RouteDefinition route;
    private final URI targetUri;

    public RouteMatch(RouteDefinition route, URI targetUri) {
        this.route = route;
        this.targetUri = targetUri;
    }

    public RouteDefinition route() {
        return route;
    }

    public URI targetUri() {
        return targetUri;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RouteMatch that = (RouteMatch) o;
        return Objects.equals(route, that.route) && Objects.equals(targetUri, that.targetUri);
    }

    @Override
    public int hashCode() {
        return Objects.hash(route, targetUri);
    }

    @Override
    public String toString() {
        return "RouteMatch{" +
                "route=" + route +
                ", targetUri=" + targetUri +
                '}';
    }
}
