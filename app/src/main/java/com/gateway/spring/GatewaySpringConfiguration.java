package com.gateway.spring;

import com.gateway.config.GatewayConfig;
import com.gateway.config.RuntimeEnvironment;
import com.gateway.routing.RouteDefinition;
import com.gateway.routing.RouteResolver;
import io.netty.channel.ChannelOption;
import org.springframework.boot.ApplicationArguments;
import org.springframework.cloud.gateway.config.HttpClientCustomizer;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;
import java.util.regex.Pattern;

@Configuration
public class GatewaySpringConfiguration {
    @Bean
    public GatewayConfig gatewayConfig(ApplicationArguments arguments) {
        return GatewayConfig.fromEnv(RuntimeEnvironment.load(arguments.getSourceArgs()).variables());
    }

    @Bean
    public HttpClientCustomizer gatewayHttpClientCustomizer(GatewayConfig config) {
        int connectTimeoutMillis = Math.toIntExact(config.requestTimeout().toMillis());
        return httpClient -> httpClient
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeoutMillis)
                .responseTimeout(config.requestTimeout());
    }

    @Bean
    public RouteResolver gatewayRouteResolver(GatewayConfig config) {
        return new RouteResolver(config.routes());
    }

    @Bean
    public RouteLocator gatewayRoutes(RouteLocatorBuilder builder, GatewayConfig config) {
        RouteLocatorBuilder.Builder routes = builder.routes();
        int index = 0;
        for (RouteDefinition route : config.routes()) {
            String routeId = route.upstreamName() + "-" + index++;
            routes.route(routeId, predicate -> predicate
                    .path(toSpringPathPattern(route.pathPattern()))
                    .filters(filters -> {
                        if (route.stripPrefix() != null && !route.stripPrefix().isBlank()) {
                            filters.rewritePath(
                                    "^" + Pattern.quote(route.stripPrefix()) + "(?<remaining>/?.*)$",
                                    "${remaining}"
                            );
                        }
                        return filters;
                    })
                    .uri(route.targetBaseUri().toString()));
        }
        return routes.build();
    }

    @Bean
    public CorsWebFilter gatewayCorsWebFilter(GatewayConfig config) {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOriginPatterns(config.allowedOrigins());
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        corsConfiguration.setAllowedHeaders(List.of("*"));
        corsConfiguration.setExposedHeaders(List.of("X-Request-Id", "X-Correlation-Id"));
        corsConfiguration.setMaxAge(600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return new CorsWebFilter(source);
    }

    private static String toSpringPathPattern(String pathPattern) {
        if (pathPattern.endsWith("/**")) {
            return pathPattern;
        }
        return pathPattern;
    }
}
