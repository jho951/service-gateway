package com.gateway.spring;

import io.github.jho951.platform.security.api.SecurityContext;
import io.github.jho951.platform.security.api.SecurityEvaluationResult;
import io.github.jho951.platform.security.api.SecurityRequest;

public interface GatewaySecurityEvaluator {
    SecurityRequest withResolvedBoundary(SecurityRequest request);

    SecurityEvaluationResult evaluateResult(SecurityRequest request, SecurityContext context);
}
