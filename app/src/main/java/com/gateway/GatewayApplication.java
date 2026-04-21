package com.gateway;

import com.gateway.config.GatewayConfig;
import com.gateway.config.RuntimeEnvironment;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * API Gateway 애플리케이션의 진입점입니다.
 * <p>
 * 이 서비스의 공식 런타임 모드는 Hybrid Embedded Gateway Mode 입니다.
 * Gateway 런타임이 filter chain을 주도하고, platform-security는 내장 policy engine과 bridge로 사용합니다.
 * </p>
 * <p>
 * 프로세스 시작 시 환경 변수를 읽어 Spring Boot 런타임을 부팅합니다.
 * 실제 프록시 처리는 Spring Cloud Gateway route/filter 체인이 담당합니다.
 * </p>
 */
@SpringBootApplication(excludeName = {
        "io.github.jho951.platform.security.autoconfigure.PlatformSecurityAutoConfiguration",
        "io.github.jho951.platform.security.internal.autoconfigure.PlatformSecurityInternalAutoConfiguration",
        "io.github.jho951.platform.security.issuer.autoconfigure.PlatformSecurityIssuerAutoConfiguration",
        "io.github.jho951.platform.security.issuer.starter.PlatformSecurityIssuerStarterAutoConfiguration",
        "org.springframework.boot.autoconfigure.security.reactive.ReactiveSecurityAutoConfiguration",
        "org.springframework.boot.autoconfigure.security.reactive.ReactiveUserDetailsServiceAutoConfiguration",
        "org.springframework.boot.autoconfigure.security.oauth2.resource.reactive.ReactiveOAuth2ResourceServerAutoConfiguration",
        "org.springframework.boot.actuate.autoconfigure.security.reactive.ReactiveManagementWebSecurityAutoConfiguration"
})
public final class GatewayApplication {
    private GatewayApplication() {}

    public static void main(String[] args) {
        RuntimeEnvironment.ResolvedEnvironment runtimeEnvironment = RuntimeEnvironment.load(args);
        GatewayConfig config = GatewayConfig.fromEnv(runtimeEnvironment.variables());

        Map<String, Object> defaults = new LinkedHashMap<>(runtimeEnvironment.variables());
        defaults.put("server.address", config.bindAddress().getHostString());
        defaults.put("server.port", String.valueOf(config.bindAddress().getPort()));
        defaults.put("spring.application.name", "gateway-service");
        defaults.put("spring.profiles.active", runtimeEnvironment.profile());
        defaults.put("spring.main.web-application-type", "reactive");
        defaults.put("spring.cloud.gateway.server.webflux.forwarded.enabled", "true");
        defaults.put("management.endpoints.web.exposure.include", "health,info,metrics,prometheus");
        defaults.put("management.endpoint.health.probes.enabled", "true");

        SpringApplication application = new SpringApplication(GatewayApplication.class);
        application.setDefaultProperties(defaults);
        application.run(args);
    }
}
