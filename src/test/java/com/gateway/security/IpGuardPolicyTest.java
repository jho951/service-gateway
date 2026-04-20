package com.gateway.security;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IpGuardPolicyTest {
    @Test
    void allowsAnyIpWithWildcardRule() {
        IpGuardPolicy policy = new IpGuardPolicy(true, List.of("*"), false);

        assertTrue(policy.allows("203.0.113.10"));
    }

    @Test
    void allowsExactIpRule() {
        IpGuardPolicy policy = new IpGuardPolicy(true, List.of("127.0.0.1"), false);

        assertTrue(policy.allows("127.0.0.1"));
        assertFalse(policy.allows("127.0.0.2"));
    }

    @Test
    void allowsCidrRule() {
        IpGuardPolicy policy = new IpGuardPolicy(true, List.of("10.0.0.0/8"), false);

        assertTrue(policy.allows("10.12.34.56"));
        assertFalse(policy.allows("11.12.34.56"));
    }

    @Test
    void usesDefaultAllowWhenNoRulesMatch() {
        IpGuardPolicy policy = new IpGuardPolicy(true, List.of("127.0.0.1"), true);

        assertTrue(policy.allows("192.0.2.10"));
    }

    @Test
    void disabledPolicyAllowsRequests() {
        IpGuardPolicy policy = new IpGuardPolicy(false, List.of(), false);

        assertTrue(policy.allows("not-an-ip"));
    }
}
