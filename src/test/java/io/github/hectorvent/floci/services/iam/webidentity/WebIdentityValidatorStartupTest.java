package io.github.hectorvent.floci.services.iam.webidentity;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.config.EmulatorConfig.IamServiceConfig.WebIdentityConfig.WebIdentityProvider;
import io.quarkus.runtime.StartupEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Optional;

import static io.github.hectorvent.floci.services.iam.webidentity.WebIdentityTestTokens.jwksFor;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Verifies the startup contract: when validation is enabled the JWKS are eagerly loaded and a
 * configured provider that cannot load fails the boot closed; when disabled, startup is a no-op.
 */
class WebIdentityValidatorStartupTest {

    private static final String ISSUER = "https://oidc.example.test";

    private final ObjectMapper mapper = new ObjectMapper();
    private final StartupEvent startupEvent = mock(StartupEvent.class);

    @Test
    void enabledWithLoadedProviderStartsCleanly(@TempDir Path tempDir) throws Exception {
        KeyPair keyPair = WebIdentityTestTokens.generateRsaKeyPair();
        Path jwks = tempDir.resolve("jwks.json");
        Files.writeString(jwks, jwksFor((RSAPublicKey) keyPair.getPublic(), "k1"));

        WebIdentityTokenValidator validator = new WebIdentityTokenValidator(
                configWith(true, List.of(provider(ISSUER, jwks.toString()))), mapper);

        assertDoesNotThrow(() -> validator.onStartup(startupEvent));
    }

    @Test
    void enabledWithUnreadableJwksFailsClosed(@TempDir Path tempDir) {
        WebIdentityTokenValidator validator = new WebIdentityTokenValidator(
                configWith(true, List.of(provider(ISSUER, tempDir.resolve("absent.json").toString()))), mapper);

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> validator.onStartup(startupEvent));
        assertTrue(ex.getMessage().contains(ISSUER), ex.getMessage());
    }

    @Test
    void enabledWithNoProvidersFailsClosed() {
        WebIdentityTokenValidator validator = new WebIdentityTokenValidator(
                configWith(true, List.of()), mapper);

        assertThrows(IllegalStateException.class, () -> validator.onStartup(startupEvent));
    }

    @Test
    void disabledIsANoOpEvenWithBrokenProvider(@TempDir Path tempDir) {
        WebIdentityTokenValidator validator = new WebIdentityTokenValidator(
                configWith(false, List.of(provider(ISSUER, tempDir.resolve("absent.json").toString()))), mapper);

        assertDoesNotThrow(() -> validator.onStartup(startupEvent));
    }

    private EmulatorConfig configWith(boolean enabled, List<WebIdentityProvider> providers) {
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        var cfg = config.services().iam().webIdentity();
        when(cfg.enabled()).thenReturn(enabled);
        when(cfg.clockSkewSeconds()).thenReturn(60L);
        when(cfg.providers()).thenReturn(providers);
        return config;
    }

    private WebIdentityProvider provider(String issuer, String jwksPath) {
        WebIdentityProvider provider = mock(WebIdentityProvider.class);
        when(provider.issuer()).thenReturn(issuer);
        when(provider.audience()).thenReturn(Optional.empty());
        when(provider.jwksPath()).thenReturn(Optional.ofNullable(jwksPath));
        return provider;
    }
}
