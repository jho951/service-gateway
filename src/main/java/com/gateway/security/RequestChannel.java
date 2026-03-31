package com.gateway.security;

import java.util.Locale;

/** 외부 요청의 인증 채널을 식별합니다. */
public enum RequestChannel {
    WEB("web"),
    NATIVE("native"),
    CLI("cli"),
    API("api");

    private final String headerValue;

    RequestChannel(String headerValue) {
        this.headerValue = headerValue;
    }

    public String headerValue() {
        return headerValue;
    }

    public boolean isWeb() {
        return this == WEB;
    }

    public boolean isTokenBased() {
        return this == NATIVE || this == CLI || this == API;
    }

    public static RequestChannel fromClientType(String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            return null;
        }
        return switch (rawValue.trim().toLowerCase(Locale.ROOT)) {
            case "web", "browser" -> WEB;
            case "native", "mobile", "app", "desktop" -> NATIVE;
            case "cli" -> CLI;
            case "api", "service", "server" -> API;
            default -> null;
        };
    }
}
