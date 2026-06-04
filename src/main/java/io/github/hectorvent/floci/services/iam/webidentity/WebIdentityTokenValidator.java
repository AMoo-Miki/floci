package io.github.hectorvent.floci.services.iam.webidentity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.JwkRsaKeys;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Verifies web-identity JWTs against statically-configured issuer JWKS.
 *
 * <p>Validation steps (all offline — no network egress):
 * <ol>
 *   <li>Split and base64url-decode the JWT; require {@code alg=RS256}.</li>
 *   <li>Resolve the issuer ({@code iss}) to its configured keys; verify the RS256 signature
 *       (preferring the {@code kid}-matched key, falling back to any configured key).</li>
 *   <li>Require {@code exp} and check it (plus {@code nbf}/{@code iat} when present) within the
 *       configured clock skew.</li>
 *   <li>Enforce {@code aud} only when the provider configured an expected audience.</li>
 * </ol>
 *
 * <p>Failures surface as {@link AwsException} with STS-appropriate codes:
 * {@code ExpiredTokenException} (400) for expiry, {@code InvalidIdentityToken} (400) for
 * everything else (malformed token, unknown issuer, bad signature, audience mismatch).
 */
@ApplicationScoped
public class WebIdentityTokenValidator {

    private static final Logger LOG = Logger.getLogger(WebIdentityTokenValidator.class);
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    /** Minimum RSA modulus accepted for a signing key; below this a key is forgeable/deprecated. */
    private static final int MIN_RSA_KEY_BITS = 2048;
    /** Upper modulus bound so a hostile JWKS cannot force pathologically expensive verifications. */
    private static final int MAX_RSA_KEY_BITS = 8192;

    /** Verified signing keys and optional expected audience for one OIDC issuer. */
    record IssuerKeys(String issuer, String expectedAudience, List<KeyEntry> keys) {}

    /** A single JWKS entry: its {@code kid} (may be {@code null}) and the RSA public key. */
    record KeyEntry(String kid, RSAPublicKey key) {}

    private final Map<String, IssuerKeys> byIssuer;
    private final long clockSkewSeconds;
    private final Clock clock;
    private final ObjectMapper mapper;

    @Inject
    public WebIdentityTokenValidator(EmulatorConfig config, ObjectMapper mapper) {
        this(buildFromConfig(config, mapper),
                config.services().iam().webIdentity().clockSkewSeconds(),
                Clock.systemUTC(),
                mapper);
    }

    /** Test constructor: inject pre-built issuer keys directly. */
    WebIdentityTokenValidator(Map<String, IssuerKeys> byIssuer, long clockSkewSeconds,
                              Clock clock, ObjectMapper mapper) {
        this.byIssuer = Map.copyOf(byIssuer);
        this.clockSkewSeconds = clockSkewSeconds;
        this.clock = clock;
        this.mapper = mapper;
    }

    /**
     * Builds the issuer-to-keys map from configuration.
     * A provider that fails to load (missing file, bad JWKS) is logged and skipped — its
     * tokens then fail validation with {@code InvalidIdentityToken} rather than crashing startup.
     */
    static Map<String, IssuerKeys> buildFromConfig(EmulatorConfig config, ObjectMapper mapper) {
        Map<String, IssuerKeys> result = new LinkedHashMap<>();
        var cfg = config.services().iam().webIdentity();
        for (var provider : cfg.providers()) {
            try {
                String jwksJson = provider.jwksPath()
                        .map(WebIdentityTokenValidator::readFile)
                        .orElse(null);
                if (jwksJson == null || jwksJson.isBlank()) {
                    LOG.warnv("Web-identity provider {0} has no jwks-path; skipping",
                            provider.issuer());
                    continue;
                }
                List<KeyEntry> keys = parseJwks(jwksJson, mapper);
                if (keys.isEmpty()) {
                    LOG.warnv("Web-identity provider {0} JWKS contained no usable RSA keys; skipping",
                            provider.issuer());
                    continue;
                }
                result.put(provider.issuer(),
                        new IssuerKeys(provider.issuer(), provider.audience().orElse(null), keys));
                LOG.infov("Loaded {0} web-identity signing key(s) for issuer {1}",
                        keys.size(), provider.issuer());
            } catch (Exception e) {
                LOG.warnv("Failed to load web-identity provider {0}: {1}",
                        provider.issuer(), e.getMessage());
            }
        }
        return result;
    }

    private static String readFile(String path) {
        try {
            return Files.readString(Path.of(path));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read JWKS file " + path + ": " + e.getMessage(), e);
        }
    }

    /** Parses a standard JWKS document into RSA key entries. Non-RSA keys are ignored. */
    static List<KeyEntry> parseJwks(String jwksJson, ObjectMapper mapper) {
        List<KeyEntry> keys = new ArrayList<>();
        try {
            JsonNode root = mapper.readTree(jwksJson);
            JsonNode keysNode = root.path("keys");
            if (!keysNode.isArray()) {
                return keys;
            }
            for (JsonNode jwk : keysNode) {
                if (!"RSA".equals(jwk.path("kty").asText())) {
                    continue;
                }
                String use = jwk.path("use").asText(null);
                if (use != null && !"sig".equals(use)) {
                    continue; // encryption-designated key must not verify signatures
                }
                String alg = jwk.path("alg").asText(null);
                if (alg != null && !"RS256".equals(alg)) {
                    continue; // only RS256 is supported
                }
                String n = jwk.path("n").asText(null);
                String e = jwk.path("e").asText(null);
                if (n == null || e == null) {
                    continue;
                }
                RSAPublicKey key = JwkRsaKeys.rsaPublicKeyFromJwk(n, e);
                int bits = key.getModulus().bitLength();
                if (bits < MIN_RSA_KEY_BITS) {
                    LOG.warnv("Skipping web-identity RSA key with {0}-bit modulus (< {1})",
                            bits, MIN_RSA_KEY_BITS);
                    continue;
                }
                if (bits > MAX_RSA_KEY_BITS) {
                    LOG.warnv("Skipping web-identity RSA key with {0}-bit modulus (> {1})",
                            bits, MAX_RSA_KEY_BITS);
                    continue;
                }
                String kid = jwk.path("kid").asText(null);
                keys.add(new KeyEntry(kid, key));
            }
        } catch (Exception ex) {
            throw new IllegalStateException("Invalid JWKS document: " + ex.getMessage(), ex);
        }
        return keys;
    }

    /**
     * Validates the given web-identity token and returns its decoded claims.
     *
     * @throws AwsException with {@code ExpiredTokenException} or {@code InvalidIdentityToken}
     */
    public WebIdentityClaims validate(String token) {
        // Retain trailing empty segments so "h.p.s." (extra dots) is rejected, not silently truncated.
        String[] parts = token == null ? new String[0] : token.split("\\.", -1);
        if (parts.length != 3) {
            throw invalid("Web identity token is not a well-formed JWT.");
        }

        JsonNode header = decodeSegment(parts[0], "header");
        if (!"RS256".equals(header.path("alg").asText())) {
            throw invalid("Unsupported web identity token signature algorithm; only RS256 is supported.");
        }
        String typ = header.path("typ").asText(null);
        if (typ != null && !"JWT".equalsIgnoreCase(typ) && !"JOSE".equalsIgnoreCase(typ)) {
            throw invalid("Unsupported web identity token typ header.");
        }
        String kid = header.path("kid").asText(null);

        JsonNode payload = decodeSegment(parts[1], "payload");
        String issuer = payload.path("iss").asText(null);
        if (issuer == null || issuer.isBlank()) {
            throw invalid("Web identity token is missing the iss claim.");
        }
        IssuerKeys issuerKeys = byIssuer.get(issuer);
        if (issuerKeys == null) {
            throw invalid("Web identity token issuer is not registered for validation: " + issuer);
        }

        if (!signatureValid(parts[0] + "." + parts[1], parts[2], issuerKeys, kid)) {
            throw invalid("Web identity token signature verification failed.");
        }

        verifyTimeClaims(payload);

        List<String> audiences = readAudiences(payload);
        if (issuerKeys.expectedAudience() != null
                && !audiences.contains(issuerKeys.expectedAudience())) {
            throw invalid("Web identity token audience does not match the configured audience.");
        }

        String subject = payload.path("sub").asText(null);
        if (subject == null || subject.isBlank()) {
            throw invalid("Web identity token is missing the sub claim.");
        }
        return new WebIdentityClaims(issuer, subject, audiences);
    }

    private boolean signatureValid(String signingInput, String signatureSegment,
                                   IssuerKeys issuerKeys, String kid) {
        byte[] expected;
        try {
            expected = URL_DECODER.decode(signatureSegment);
        } catch (IllegalArgumentException e) {
            return false;
        }
        List<KeyEntry> ordered = orderedKeys(issuerKeys, kid);
        byte[] signingBytes = signingInput.getBytes(StandardCharsets.UTF_8);
        boolean anyVerifyCompleted = false;
        String lastError = null;
        for (KeyEntry entry : ordered) {
            try {
                Signature verifier = Signature.getInstance("SHA256withRSA");
                verifier.initVerify(entry.key());
                verifier.update(signingBytes);
                boolean matched = verifier.verify(expected);
                anyVerifyCompleted = true;
                if (matched) {
                    return true;
                }
            } catch (Exception e) {
                lastError = e.getMessage();
            }
        }
        // Distinguish "no key matched" (ordinary bad signature) from "every key threw"
        // (likely provider/key misconfiguration), surfacing the latter once at WARN.
        if (!ordered.isEmpty() && !anyVerifyCompleted) {
            LOG.warnv("Web-identity signature verification errored for all {0} key(s) of issuer {1}: {2}",
                    ordered.size(), issuerKeys.issuer(), lastError);
        }
        return false;
    }

    /** Returns the issuer keys with the {@code kid}-matched key(s) first, then the remainder. */
    private static List<KeyEntry> orderedKeys(IssuerKeys issuerKeys, String kid) {
        List<KeyEntry> keys = issuerKeys.keys();
        if (kid == null) {
            return keys;
        }
        List<KeyEntry> ordered = new ArrayList<>(keys.size());
        List<KeyEntry> rest = new ArrayList<>();
        for (KeyEntry entry : keys) {
            if (kid.equals(entry.kid())) {
                ordered.add(entry);
            } else {
                rest.add(entry);
            }
        }
        ordered.addAll(rest);
        return ordered;
    }

    private void verifyTimeClaims(JsonNode payload) {
        long now = clock.instant().getEpochSecond();
        // exp is REQUIRED by OIDC Core; on a credential-minting boundary the freshness
        // control must fail closed rather than accept an unbounded (replayable) token.
        JsonNode expNode = payload.get("exp");
        if (expNode == null || !expNode.isNumber()) {
            throw invalid("Web identity token is missing or has a non-numeric exp claim.");
        }
        long exp = expNode.asLong();
        if (now > exp + clockSkewSeconds) {
            throw new AwsException("ExpiredTokenException",
                    "Web identity token has expired.", 400);
        }
        if (payload.has("nbf")) {
            long nbf = payload.get("nbf").asLong();
            if (now + clockSkewSeconds < nbf) {
                throw invalid("Web identity token is not yet valid (nbf).");
            }
        }
        if (payload.has("iat")) {
            long iat = payload.get("iat").asLong();
            if (now + clockSkewSeconds < iat) {
                throw invalid("Web identity token issued-at (iat) is in the future.");
            }
        }
    }

    private List<String> readAudiences(JsonNode payload) {
        JsonNode aud = payload.get("aud");
        List<String> audiences = new ArrayList<>();
        if (aud == null || aud.isNull()) {
            return audiences;
        }
        if (aud.isArray()) {
            aud.forEach(a -> audiences.add(a.asText()));
        } else {
            audiences.add(aud.asText());
        }
        return audiences;
    }

    private JsonNode decodeSegment(String segment, String name) {
        try {
            return mapper.readTree(URL_DECODER.decode(segment));
        } catch (Exception e) {
            throw invalid("Web identity token " + name + " is not valid base64url JSON.");
        }
    }

    /**
     * Returns the AWS-correct {@code InvalidIdentityToken} error. All rejection reasons collapse to
     * one constant client message — the discriminating {@code detail} stays at DEBUG so the response
     * cannot be used to enumerate the configured issuer registry or echo attacker-supplied input.
     */
    private static AwsException invalid(String detail) {
        LOG.debugv("Web-identity token rejected: {0}", detail);
        return new AwsException("InvalidIdentityToken", INVALID_TOKEN_MESSAGE, 400);
    }

    private static final String INVALID_TOKEN_MESSAGE =
            "The web identity token that was passed could not be validated.";
}
