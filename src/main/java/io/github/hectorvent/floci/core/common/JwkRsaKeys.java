package io.github.hectorvent.floci.core.common;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * Shared codec for the JWK RSA key representation (RFC 7517/7518): the unsigned big-endian,
 * base64url-without-padding encoding of the modulus ({@code n}) and exponent ({@code e}), and the
 * reconstruction of an {@link RSAPublicKey} from that pair.
 *
 * <p>Both directions of the round-trip live here so they cannot drift: Cognito's JWKS endpoint
 * emits keys via {@link #encodeUnsigned(BigInteger)}, and web-identity token validation parses
 * them via {@link #rsaPublicKeyFromJwk(String, String)}.
 */
public final class JwkRsaKeys {

    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    private JwkRsaKeys() {
    }

    /** Encodes a non-negative big integer as unsigned big-endian base64url (no padding). */
    public static String encodeUnsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        // BigInteger#toByteArray prepends a 0x00 sign byte when the high bit is set; JWK n/e are
        // unsigned, so strip the leading zero.
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return URL_ENCODER.encodeToString(bytes);
    }

    /** Decodes an unsigned big-endian base64url value (JWK {@code n}/{@code e}) to a BigInteger. */
    public static BigInteger decodeUnsigned(String base64Url) {
        return new BigInteger(1, URL_DECODER.decode(base64Url));
    }

    /** Reconstructs an RSA public key from the JWK {@code n} and {@code e} parameters. */
    public static RSAPublicKey rsaPublicKeyFromJwk(String n, String e) throws GeneralSecurityException {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(decodeUnsigned(n), decodeUnsigned(e));
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    }
}
