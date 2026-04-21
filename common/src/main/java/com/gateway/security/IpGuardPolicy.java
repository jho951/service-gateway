package com.gateway.security;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 게이트웨이용 IP 허용 정책입니다.
 */
public final class IpGuardPolicy {
    private final boolean enabled;
    private final List<IpRule> rules;
    private final boolean defaultAllow;

    /**
     * @param enabled 정책 활성화 여부
     * @param rules raw IP 허용 규칙 목록. {@code *}, 단일 IP, CIDR을 지원합니다.
     * @param defaultAllow 규칙 미일치 시 기본 허용 여부
     */
    public IpGuardPolicy(boolean enabled, List<String> rules, boolean defaultAllow) {
        this.enabled = enabled;
        this.rules = compileRules(rules);
        this.defaultAllow = defaultAllow;
    }

    /**
     * 클라이언트 IP가 현재 정책상 허용되는지 검사합니다.
     *
     * @param clientIp 검사할 원격 IP 문자열
     * @return 허용되면 {@code true}
     */
    public boolean allows(String clientIp) {
        if (!enabled) return true;
        if (clientIp == null || clientIp.isBlank()) return false;

        InetAddress address = parseIp(clientIp);
        if (address == null) return false;

        for (IpRule rule : rules) {
            if (rule.matches(address)) return true;
        }
        return defaultAllow;
    }

    public boolean enabled() {
        return enabled;
    }

    public int ruleCount() {
        return rules.size();
    }

    public boolean defaultAllow() {
        return defaultAllow;
    }

    private static List<IpRule> compileRules(List<String> rawRules) {
        if (rawRules == null || rawRules.isEmpty()) return List.of();

        List<IpRule> compiled = new ArrayList<>();
        for (String rawRule : rawRules) {
            IpRule rule = compileRule(rawRule);
            if (rule != null) compiled.add(rule);
        }
        return List.copyOf(compiled);
    }

    private static IpRule compileRule(String rawRule) {
        if (rawRule == null || rawRule.isBlank()) return null;

        String rule = rawRule.trim();
        if ("*".equals(rule)) return address -> true;

        int slashIndex = rule.indexOf('/');
        if (slashIndex < 0) {
            InetAddress address = parseIp(rule);
            if (address == null) return null;
            return candidate -> addressesEqual(address, candidate);
        }

        InetAddress network = parseIp(rule.substring(0, slashIndex));
        if (network == null) return null;

        int prefixLength;
        try {
            prefixLength = Integer.parseInt(rule.substring(slashIndex + 1));
        } catch (NumberFormatException ex) {
            return null;
        }

        byte[] networkBytes = network.getAddress();
        int maxPrefixLength = networkBytes.length * 8;
        if (prefixLength < 0 || prefixLength > maxPrefixLength) return null;

        return candidate -> matchesCidr(networkBytes, prefixLength, candidate.getAddress());
    }

    private static InetAddress parseIp(String rawIp) {
        if (rawIp == null || rawIp.isBlank()) return null;

        String ip = rawIp.trim();
        if (!ip.matches("[0-9A-Fa-f:.]+")) return null;

        try {
            return InetAddress.getByName(ip);
        } catch (UnknownHostException ex) {
            return null;
        }
    }

    private static boolean addressesEqual(InetAddress expected, InetAddress candidate) {
        return Arrays.equals(expected.getAddress(), candidate.getAddress());
    }

    private static boolean matchesCidr(byte[] networkBytes, int prefixLength, byte[] candidateBytes) {
        if (networkBytes.length != candidateBytes.length) return false;

        int fullBytes = prefixLength / 8;
        for (int i = 0; i < fullBytes; i++) {
            if (networkBytes[i] != candidateBytes[i]) return false;
        }

        int remainingBits = prefixLength % 8;
        if (remainingBits == 0) return true;

        int mask = 0xFF << (8 - remainingBits);
        return (networkBytes[fullBytes] & mask) == (candidateBytes[fullBytes] & mask);
    }

    private interface IpRule {
        boolean matches(InetAddress address);
    }
}
