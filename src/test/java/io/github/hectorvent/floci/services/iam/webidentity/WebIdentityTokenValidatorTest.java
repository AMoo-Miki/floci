package io.github.hectorvent.floci.services.iam.webidentity;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static io.github.hectorvent.floci.services.iam.webidentity.WebIdentityTestTokens.jwksFor;
import static io.github.hectorvent.floci.services.iam.webidentity.WebIdentityTestTokens.sign;
import static org.junit.jupiter.api.Assertions.*;

class WebIdentityTokenValidatorTest {

    private static final String ISSUER = "https://token.actions.githubusercontent.com";
    private static final long NOW = 1_900_000_000L; // fixed reference time

    private final ObjectMapper mapper = new ObjectMapper();
    private KeyPair keyPair;
    private KeyPair otherKeyPair;
    private WebIdentityTokenValidator validator;

    @BeforeEach
    void setUp() throws Exception {
        keyPair = WebIdentityTestTokens.generateRsaKeyPair();
        otherKeyPair = WebIdentityTestTokens.generateRsaKeyPair();

        String jwks = jwksFor((RSAPublicKey) keyPair.getPublic(), "test-key");
        List<WebIdentityTokenValidator.KeyEntry> keys =
                WebIdentityTokenValidator.parseJwks(jwks, mapper);
        var issuerKeys = new WebIdentityTokenValidator.IssuerKeys(ISSUER, "sts.amazonaws.com", keys);

        validator = new WebIdentityTokenValidator(
                Map.of(ISSUER, issuerKeys),
                60,
                Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC),
                mapper);
    }

    @Test
    void validTokenReturnsRealClaims() {
        String token = sign(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test-key\"}",
                "{\"iss\":\"" + ISSUER + "\",\"sub\":\"repo:acme/widgets:ref:refs/heads/main\","
                        + "\"aud\":\"sts.amazonaws.com\",\"exp\":" + (NOW + 3600) + ",\"iat\":" + NOW + "}",
                keyPair.getPrivate());

        WebIdentityClaims claims = validator.validate(token);

        assertEquals(ISSUER, claims.issuer());
        assertEquals("repo:acme/widgets:ref:refs/heads/main", claims.subject());
        assertEquals(List.of("sts.amazonaws.com"), claims.audiences());
    }

    @Test
    void badSignatureRejected() {
        // Signed with a key that is not in the JWKS.
        String token = sign(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test-key\"}",
                "{\"iss\":\"" + ISSUER + "\",\"sub\":\"s\",\"aud\":\"sts.amazonaws.com\",\"exp\":"
                        + (NOW + 3600) + "}",
                otherKeyPair.getPrivate());

        AwsException ex = assertThrows(AwsException.class, () -> validator.validate(token));
        assertEquals("InvalidIdentityToken", ex.getErrorCode());
    }

    @Test
    void expiredTokenRejected() {
        String token = sign(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test-key\"}",
                "{\"iss\":\"" + ISSUER + "\",\"sub\":\"s\",\"aud\":\"sts.amazonaws.com\",\"exp\":"
                        + (NOW - 3600) + "}",
                keyPair.getPrivate());

        AwsException ex = assertThrows(AwsException.class, () -> validator.validate(token));
        assertEquals("ExpiredTokenException", ex.getErrorCode());
    }

    @Test
    void audienceMismatchRejected() {
        String token = sign(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test-key\"}",
                "{\"iss\":\"" + ISSUER + "\",\"sub\":\"s\",\"aud\":\"wrong-audience\",\"exp\":"
                        + (NOW + 3600) + "}",
                keyPair.getPrivate());

        AwsException ex = assertThrows(AwsException.class, () -> validator.validate(token));
        assertEquals("InvalidIdentityToken", ex.getErrorCode());
    }

    @Test
    void unknownIssuerRejected() {
        String token = sign(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test-key\"}",
                "{\"iss\":\"https://evil.example.com\",\"sub\":\"s\",\"aud\":\"sts.amazonaws.com\",\"exp\":"
                        + (NOW + 3600) + "}",
                keyPair.getPrivate());

        AwsException ex = assertThrows(AwsException.class, () -> validator.validate(token));
        assertEquals("InvalidIdentityToken", ex.getErrorCode());
    }

    @Test
    void malformedTokenRejected() {
        AwsException ex = assertThrows(AwsException.class,
                () -> validator.validate("garbage-not-a-jwt"));
        assertEquals("InvalidIdentityToken", ex.getErrorCode());
    }

    @Test
    void nonRs256Rejected() {
        String token = sign(
                "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
                "{\"iss\":\"" + ISSUER + "\",\"sub\":\"s\",\"aud\":\"sts.amazonaws.com\",\"exp\":"
                        + (NOW + 3600) + "}",
                keyPair.getPrivate());

        AwsException ex = assertThrows(AwsException.class, () -> validator.validate(token));
        assertEquals("InvalidIdentityToken", ex.getErrorCode());
    }

    @Test
    void noExpClaimRejected() {
        // exp is mandatory: a validly-signed token that omits exp must be rejected, not accepted
        // forever.
        String token = sign(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test-key\"}",
                "{\"iss\":\"" + ISSUER + "\",\"sub\":\"s\",\"aud\":\"sts.amazonaws.com\"}",
                keyPair.getPrivate());

        AwsException ex = assertThrows(AwsException.class, () -> validator.validate(token));
        assertEquals("InvalidIdentityToken", ex.getErrorCode());
    }

    @Test
    void nonNumericExpRejected() {
        String token = sign(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test-key\"}",
                "{\"iss\":\"" + ISSUER + "\",\"sub\":\"s\",\"aud\":\"sts.amazonaws.com\",\"exp\":\"soon\"}",
                keyPair.getPrivate());

        AwsException ex = assertThrows(AwsException.class, () -> validator.validate(token));
        assertEquals("InvalidIdentityToken", ex.getErrorCode());
    }

    @Test
    void multiAudArrayValidatesAgainstFullList() {
        // Validator accepts when any audience in the array matches the configured expected audience,
        // and the full list is preserved for the trust evaluator (no first-only truncation).
        String token = sign(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test-key\"}",
                "{\"iss\":\"" + ISSUER + "\",\"sub\":\"s\",\"aud\":[\"other\",\"sts.amazonaws.com\"],\"exp\":"
                        + (NOW + 3600) + "}",
                keyPair.getPrivate());

        WebIdentityClaims claims = validator.validate(token);
        assertEquals(List.of("other", "sts.amazonaws.com"), claims.audiences());
    }

    @Test
    void missingIssRejected() {
        String token = sign(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test-key\"}",
                "{\"sub\":\"s\",\"aud\":\"sts.amazonaws.com\",\"exp\":" + (NOW + 3600) + "}",
                keyPair.getPrivate());

        AwsException ex = assertThrows(AwsException.class, () -> validator.validate(token));
        assertEquals("InvalidIdentityToken", ex.getErrorCode());
    }

    @Test
    void missingSubRejected() {
        // A blank subject would otherwise mint credentials with an empty SubjectFromWebIdentityToken.
        String token = sign(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test-key\"}",
                "{\"iss\":\"" + ISSUER + "\",\"aud\":\"sts.amazonaws.com\",\"exp\":" + (NOW + 3600) + "}",
                keyPair.getPrivate());

        AwsException ex = assertThrows(AwsException.class, () -> validator.validate(token));
        assertEquals("InvalidIdentityToken", ex.getErrorCode());
    }

    @Test
    void nbfInFutureRejected() {
        String token = sign(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test-key\"}",
                "{\"iss\":\"" + ISSUER + "\",\"sub\":\"s\",\"aud\":\"sts.amazonaws.com\",\"exp\":"
                        + (NOW + 3600) + ",\"nbf\":" + (NOW + 3600) + "}",
                keyPair.getPrivate());

        AwsException ex = assertThrows(AwsException.class, () -> validator.validate(token));
        assertEquals("InvalidIdentityToken", ex.getErrorCode());
    }

    @Test
    void iatInFutureRejected() {
        String token = sign(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test-key\"}",
                "{\"iss\":\"" + ISSUER + "\",\"sub\":\"s\",\"aud\":\"sts.amazonaws.com\",\"exp\":"
                        + (NOW + 3600) + ",\"iat\":" + (NOW + 3600) + "}",
                keyPair.getPrivate());

        AwsException ex = assertThrows(AwsException.class, () -> validator.validate(token));
        assertEquals("InvalidIdentityToken", ex.getErrorCode());
    }

    @Test
    void algNoneRejected() {
        // Classic JWT downgrade: alg=none must be rejected at the algorithm gate.
        String token = WebIdentityTestTokens.encodeSegment("{\"alg\":\"none\",\"typ\":\"JWT\"}")
                + "." + WebIdentityTestTokens.encodeSegment(
                        "{\"iss\":\"" + ISSUER + "\",\"sub\":\"s\",\"exp\":" + (NOW + 3600) + "}")
                + ".";

        AwsException ex = assertThrows(AwsException.class, () -> validator.validate(token));
        assertEquals("InvalidIdentityToken", ex.getErrorCode());
    }

    @Test
    void headerNotBase64UrlRejected() {
        String token = "!!!." + WebIdentityTestTokens.encodeSegment(
                "{\"iss\":\"" + ISSUER + "\",\"sub\":\"s\",\"exp\":" + (NOW + 3600) + "}") + ".sig";

        AwsException ex = assertThrows(AwsException.class, () -> validator.validate(token));
        assertEquals("InvalidIdentityToken", ex.getErrorCode());
    }

}
