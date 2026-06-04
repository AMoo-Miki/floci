package io.github.hectorvent.floci.services.iam.webidentity;

import java.util.List;

/**
 * Decoded, verified claims extracted from a web-identity JWT.
 *
 * @param issuer     the token {@code iss}
 * @param subject    the token {@code sub}
 * @param audiences  the token {@code aud} (single value or array, normalized to a list)
 */
public record WebIdentityClaims(String issuer, String subject, List<String> audiences) {
}
