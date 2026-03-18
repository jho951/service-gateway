package com.gateway.security;

import com.ipguard.spi.RuleSource;
import com.ipguard.core.engine.IpGuardEngine;

import java.util.List;

/**
 * `ip-guard` OSS를 감싸는 게이트웨이용 IP 허용 정책 래퍼입니다.
 *
 * <p>규칙 문법 해석과 판정은 {@link IpGuardEngine} 에 위임합니다. 게이트웨이는
 * 규칙 원본을 조합하고 활성화 여부만 관리합니다.</p>
 */
public final class IpGuardPolicy {
    private final boolean enabled;
    private final IpGuardEngine engine;

    /**
     * @param enabled 정책 활성화 여부
     * @param rules `ip-guard`가 이해할 수 있는 IP 규칙 목록
     * @param defaultAllow 규칙 미일치 시 기본 허용 여부
     */
    public IpGuardPolicy(boolean enabled, List<String> rules, boolean defaultAllow) {
        this.enabled = enabled;
        if (!enabled) {
            this.engine = null;
            return;
        }
        RuleSource source = () -> String.join("\n", rules);
        this.engine = new IpGuardEngine(source, defaultAllow);
    }

    /**
     * 클라이언트 IP가 현재 정책상 허용되는지 검사합니다.
     *
     * @param clientIp 검사할 원격 IP 문자열
     * @return 허용되면 {@code true}
     */
    public boolean allows(String clientIp) {
        if (!enabled) {
            return true;
        }
        return engine.decide(clientIp).allowed();
    }
}
