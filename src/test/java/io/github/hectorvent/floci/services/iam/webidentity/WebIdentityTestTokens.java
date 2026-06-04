package io.github.hectorvent.floci.services.iam.webidentity;

import io.github.hectorvent.floci.core.common.JwkRsaKeys;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 * Shared test fixture for minting and publishing RS256 web-identity JWTs, so the signing/JWKS
 * helpers live in one place instead of being copied across the validator, trust, and handler tests.
 */
public final class WebIdentityTestTokens {

    private static final Base64.Encoder URL = Base64.getUrlEncoder().withoutPadding();

    private WebIdentityTestTokens() {
    }

    /** Generates a fresh 2048-bit RSA key pair (keys are never hard-coded in tests). */
    public static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Builds a JWKS document advertising {@code key} under {@code kid} (kty=RSA, alg=RS256, use=sig). */
    public static String jwksFor(RSAPublicKey key, String kid) {
        String n = JwkRsaKeys.encodeUnsigned(key.getModulus());
        String e = JwkRsaKeys.encodeUnsigned(key.getPublicExponent());
        return "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"" + kid + "\",\"alg\":\"RS256\",\"use\":\"sig\","
                + "\"n\":\"" + n + "\",\"e\":\"" + e + "\"}]}";
    }

    /** Signs {@code header}.{@code payload} with the RSA private key and returns the compact JWT. */
    public static String sign(String headerJson, String payloadJson, PrivateKey key) {
        String signingInput = encodeSegment(headerJson) + "." + encodeSegment(payloadJson);
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(key);
            signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return signingInput + "." + URL.encodeToString(signature.sign());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Base64url-encodes a single JWT segment (handy for assembling malformed tokens). */
    public static String encodeSegment(String json) {
        return URL.encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
