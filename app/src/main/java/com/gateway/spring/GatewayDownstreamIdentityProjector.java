package com.gateway.spring;

import io.github.jho951.platform.security.api.SecurityEvaluationResult;

import java.util.Map;

public interface GatewayDownstreamIdentityProjector {
    Map<String, String> asAttributes(SecurityEvaluationResult evaluationResult);
}
