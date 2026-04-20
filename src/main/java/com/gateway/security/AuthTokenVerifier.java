package com.gateway.security;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * auth-service가 발행한 JWT를 검증합니다.
 *
 * <p>서명을 검증하고, iss/aud/exp 클레임을 확인함으로써 게이트웨이만의 신뢰 경계를 강화합니다.</p>
 */
public final class AuthTokenVerifier {
    private static final Pattern AUD_ARRAY = Pattern.compile("\"aud\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL);
    private static final Pattern ARRAY_VALUE = Pattern.compile("\"([^\"]+)\"");

    private final boolean enabled;
    private final PublicKey publicKey;
    private final boolean useSharedSecret;
    private final byte[] sharedSecretBytes;
    private final String expectedAlgorithm;
    private final String keyId;
    private final String issuer;
    private final String audience;
    private final long clockSkewSeconds;

    public AuthTokenVerifier(
            boolean enabled,
            String publicKeyPem,
            String sharedSecret,
            String keyId,
            String algorithm,
            String issuer,
            String audience,
            long clockSkewSeconds
    ) {
        this.enabled = enabled;
        this.expectedAlgorithm = normalizeAlgorithm(algorithm);
        String algorithmUpper = expectedAlgorithm == null ? "" : expectedAlgorithm.toUpperCase(Locale.ROOT);
        boolean expectsHs = algorithmUpper.startsWith("HS");
        boolean expectsRs = algorithmUpper.startsWith("RS");
        this.useSharedSecret = enabled && expectsHs && sharedSecret != null && !sharedSecret.isBlank();
        this.sharedSecretBytes = useSharedSecret ? sharedSecret.getBytes(StandardCharsets.UTF_8) : null;
        if (enabled && expectsHs && !useSharedSecret) {
            throw new IllegalArgumentException("AUTH_JWT_SHARED_SECRET must be configured when AUTH_JWT_ALGORITHM starts with HS");
        }
        if (enabled && expectsRs && (publicKeyPem == null || publicKeyPem.isBlank())) {
            throw new IllegalArgumentException("AUTH_JWT_PUBLIC_KEY_PEM must be configured when AUTH_JWT_ALGORITHM starts with RS");
        }
        this.publicKey = (enabled && expectsRs) ? loadPublicKey(publicKeyPem) : null;
        this.keyId = keyId;
        this.issuer = issuer;
        this.audience = audience;
        this.clockSkewSeconds = Math.max(0L, clockSkewSeconds);
    }

    public Result verify(String authorizationHeader) {
        if (!enabled) {
            return Result.skipped("JWT_VERIFICATION_DISABLED");
        }
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return Result.rejected("MISSING_AUTH_HEADER");
        }
        if (!authorizationHeader.startsWith("Bearer ")) {
            return Result.rejected("INVALID_AUTH_SCHEME");
        }
        String token = authorizationHeader.substring("Bearer ".length()).trim();
        if (token.isEmpty()) {
            return Result.rejected("EMPTY_BEARER_TOKEN");
        }
        String[] segments = token.split("\\.", -1);
        if (segments.length != 3) {
            return Result.rejected("INVALID_JWT_PARTS");
        }
        for (String segment : segments) {
            if (segment.isBlank()) return Result.rejected("INVALID_JWT_SEGMENT");
        }

        String headerJson = decodeSegment(segments[0]);
        String payloadJson = decodeSegment(segments[1]);
        if (headerJson == null || payloadJson == null) return Result.rejected("INVALID_JWT_PAYLOAD");

        byte[] signature = decodeSignature(segments[2]);
        if (signature == null) return Result.rejected("INVALID_JWT_SIGNATURE");

        String alg = extractStringClaim(headerJson, "alg");
        if (alg == null) return Result.rejected("MISSING_ALGORITHM");
        if (!expectedAlgorithm.equalsIgnoreCase(alg)) return Result.rejected("UNEXPECTED_ALGORITHM");

        if (keyId != null && !keyId.isBlank()) {
            String kid = extractStringClaim(headerJson, "kid");
            if (kid == null || !keyId.equals(kid)) return Result.rejected("KEY_ID_MISMATCH");
        }

        String signingInput = segments[0] + "." + segments[1];
        if (useSharedSecret) {
            String macAlgorithm = toMacAlgorithm(alg);
            if (macAlgorithm == null) return Result.rejected("UNSUPPORTED_ALGORITHM");
            if (!verifyMac(signingInput, macAlgorithm, signature)) return Result.rejected("SIGNATURE_VERIFICATION_FAILED");
        } else {
            String signatureAlgorithm = toSignatureAlgorithm(alg);
            if (signatureAlgorithm == null) return Result.rejected("UNSUPPORTED_ALGORITHM");
            if (!verifySignature(signingInput, signatureAlgorithm, signature)) return Result.rejected("SIGNATURE_VERIFICATION_FAILED");
        }

        if (issuer != null && !issuer.isBlank()) {
            String issClaim = extractStringClaim(payloadJson, "iss");
            if (issClaim == null || !issuer.equals(issClaim)) return Result.rejected("ISSUER_MISMATCH");
        }

        if (audience != null && !audience.isBlank() && !matchesAudience(payloadJson, audience)) return Result.rejected("AUDIENCE_MISMATCH");

        Long expSeconds = extractNumberClaim(payloadJson, "exp");
        if (expSeconds == null) return Result.rejected("EXP_CLAIM_MISSING");
        long now = Instant.now().getEpochSecond();
        if (now > expSeconds + clockSkewSeconds) return Result.rejected("TOKEN_EXPIRED");
        return Result.verified("TOKEN_VERIFIED");
    }

    private boolean verifySignature(String signingInput, String signatureAlgorithm, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance(signatureAlgorithm);
            verifier.initVerify(publicKey);
            verifier.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return verifier.verify(signature);
        } catch (GeneralSecurityException ex) {
            return false;
        }
    }

    private boolean verifyMac(String signingInput, String macAlgorithm, byte[] signature) {
        if (sharedSecretBytes == null) return false;
        try {
            Mac mac = Mac.getInstance(macAlgorithm);
            mac.init(new SecretKeySpec(sharedSecretBytes, macAlgorithm));
            byte[] expected = mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII));
            return MessageDigest.isEqual(expected, signature);
        } catch (GeneralSecurityException ex) {
            return false;
        }
    }

    private String decodeSegment(String segment) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(segment);
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private byte[] decodeSignature(String segment) {
        try {
            return Base64.getUrlDecoder().decode(segment);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private static String extractStringClaim(String json, String claimName) {
        Pattern pattern = Pattern.compile(String.format("\"%s\"\\s*:\\s*\"([^\"]+)\"", Pattern.quote(claimName)));
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) return matcher.group(1);
        return null;
    }

    private static Long extractNumberClaim(String json, String claimName) {
        Pattern pattern = Pattern.compile(String.format("\"%s\"\\s*:\\s*(\\d+)", Pattern.quote(claimName)));
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            try {
                return Long.parseLong(matcher.group(1));
            } catch (NumberFormatException ex) {
                return null;
            }
        }
        return null;
    }

    private boolean matchesAudience(String payloadJson, String expected) {
        String single = extractStringClaim(payloadJson, "aud");
        if (expected.equals(single)) return true;
        Matcher arrayMatcher = AUD_ARRAY.matcher(payloadJson);
        if (!arrayMatcher.find()) return false;
        String list = arrayMatcher.group(1);
        Matcher valueMatcher = ARRAY_VALUE.matcher(list);
        while (valueMatcher.find()) {
            if (expected.equals(valueMatcher.group(1))) return true;
        }
        return false;
    }

    private static String normalizeAlgorithm(String algorithm) {
        if (algorithm == null) return "RS256";
        if (algorithm.isBlank()) return "RS256";
        return algorithm.trim();
    }

    private static String toSignatureAlgorithm(String jwtAlg) {
        if (jwtAlg == null) return null;
        return switch (jwtAlg.toUpperCase(Locale.ROOT)) {
            case "RS256" -> "SHA256withRSA";
            case "RS384" -> "SHA384withRSA";
            case "RS512" -> "SHA512withRSA";
            default -> null;
        };
    }

    private static String toMacAlgorithm(String jwtAlg) {
        if (jwtAlg == null) return null;
        return switch (jwtAlg.toUpperCase(Locale.ROOT)) {
            case "HS256" -> "HmacSHA256";
            case "HS384" -> "HmacSHA384";
            case "HS512" -> "HmacSHA512";
            default -> null;
        };
    }

    private static PublicKey loadPublicKey(String pem) {
        String cleaned = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(cleaned);
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(new X509EncodedKeySpec(decoded));
        } catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("Invalid AUTH_JWT_PUBLIC_KEY_PEM", ex);
        }
    }

    public record Result(boolean performed, boolean verified, String outcome) {
        public static Result skipped(String outcome) {
            return new Result(false, true, outcome);
        }
        public static Result verified(String outcome) {
            return new Result(true, true, outcome);
        }
        public static Result rejected(String outcome) {
            return new Result(true, false, outcome);
        }
    }
}
