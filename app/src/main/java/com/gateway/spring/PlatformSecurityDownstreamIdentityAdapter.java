package com.gateway.spring;

import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.web.SecurityDownstreamIdentityPropagator;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public final class PlatformSecurityDownstreamIdentityAdapter implements GatewayDownstreamIdentityProjector {
    private final SecurityDownstreamIdentityPropagator delegate = new SecurityDownstreamIdentityPropagator();

    @Override
    public Map<String, String> asAttributes(SecurityEvaluationResult evaluationResult) {
        return delegate.asAttributes(evaluationResult);
    }
}
