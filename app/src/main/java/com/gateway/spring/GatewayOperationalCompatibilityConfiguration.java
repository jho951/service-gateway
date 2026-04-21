package com.gateway.spring;

import com.gateway.config.GatewayConfig;
import com.gateway.security.IpGuardPolicy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
public class GatewayOperationalCompatibilityConfiguration {

    @Bean
    public SmartInitializingSingleton gatewayOperationalCompatibilityGuard(
            GatewayConfig config,
            Environment environment
    ) {
        return () -> {
            if (!isProduction(environment.getActiveProfiles())) {
                return;
            }

            List<String> violations = new ArrayList<>();
            validateIpPolicy("gateway admin ip policy", config.adminIpPolicy(), violations);
            validateIpPolicy("gateway internal ip policy", config.internalIpPolicy(), violations);
            if (config.loginRateLimitPerMinute() <= 0) {
                violations.add("GATEWAY_LOGIN_RATE_LIMIT_PER_MINUTE must be greater than 0 in production");
            }
            validateSecret("AUTH_SERVICE_INTERNAL_REQUEST_SECRET", config.authServiceInternalRequestSecret(), violations);
            validateSecret("GATEWAY_INTERNAL_REQUEST_SECRET", config.internalRequestSecret(), violations);
            validateSecret("AUTHZ_INTERNAL_JWT_SECRET", config.authzInternalJwtSharedSecret(), violations);

            if (!violations.isEmpty()) {
                throw new IllegalStateException("Gateway operational compatibility violation: " + String.join("; ", violations));
            }
        };
    }

    private static boolean isProduction(String[] activeProfiles) {
        return Arrays.stream(activeProfiles == null ? new String[0] : activeProfiles)
                .anyMatch(profile -> "prod".equalsIgnoreCase(profile) || "production".equalsIgnoreCase(profile) || "live".equalsIgnoreCase(profile));
    }

    private static void validateIpPolicy(String name, IpGuardPolicy policy, List<String> violations) {
        if (!policy.enabled()) {
            violations.add(name + " must be enabled in production");
            return;
        }
        if (policy.defaultAllow()) {
            violations.add(name + " must not default-allow in production");
        }
        if (policy.ruleCount() == 0) {
            violations.add(name + " must define at least one allow rule in production");
        }
    }

    private static void validateSecret(String name, String value, List<String> violations) {
        if (value == null || value.isBlank()) {
            violations.add(name + " must be configured in production");
            return;
        }
        if ("dev-internal-jwt-secret".equals(value)) {
            violations.add(name + " must not use the gateway development fallback in production");
        }
    }
}
