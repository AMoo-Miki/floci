package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AccountResolver;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.github.hectorvent.floci.services.iam.webidentity.WebIdentityTestTokens;
import io.github.hectorvent.floci.services.iam.webidentity.WebIdentityTokenValidator;
import io.github.hectorvent.floci.services.iam.webidentity.WebIdentityTrustEvaluator;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

import static io.github.hectorvent.floci.services.iam.webidentity.WebIdentityTestTokens.jwksFor;
import static io.github.hectorvent.floci.services.iam.webidentity.WebIdentityTestTokens.sign;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class StsWebIdentityHandlerTest {

    private static final String ISSUER = "https://token.actions.githubusercontent.com";

    private final ObjectMapper mapper = new ObjectMapper();
    private EmulatorConfig.IamServiceConfig.WebIdentityConfig webIdentityCfg;
    private IamService iamService;
    private StsQueryHandler handler;
    private KeyPair keyPair;
    private String roleArn;

    @BeforeEach
    void setUp(@TempDir Path tempDir) throws Exception {
        keyPair = WebIdentityTestTokens.generateRsaKeyPair();

        Path jwksFile = tempDir.resolve("jwks.json");
        Files.writeString(jwksFile, jwksFor((RSAPublicKey) keyPair.getPublic(), "k1"));

        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        webIdentityCfg = config.services().iam().webIdentity();

        var provider = mock(EmulatorConfig.IamServiceConfig.WebIdentityConfig.WebIdentityProvider.class);
        when(provider.issuer()).thenReturn(ISSUER);
        when(provider.audience()).thenReturn(Optional.empty());
        when(provider.jwksPath()).thenReturn(Optional.of(jwksFile.toString()));

        when(webIdentityCfg.providers()).thenReturn(java.util.List.of(provider));
        when(webIdentityCfg.clockSkewSeconds()).thenReturn(60L);

        RegionResolver regionResolver = new RegionResolver("us-east-1", "000000000000");
        AccountResolver accountResolver = new AccountResolver("000000000000");
        iamService = new IamService(
                new InMemoryStorage<>(), new InMemoryStorage<>(), new InMemoryStorage<>(),
                new InMemoryStorage<>(), new InMemoryStorage<>(), new InMemoryStorage<>(),
                new InMemoryStorage<>(), regionResolver);

        String trust = "{\"Version\":\"2012-10-17\",\"Statement\":[{"
                + "\"Effect\":\"Allow\","
                + "\"Principal\":{\"Federated\":\"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com\"},"
                + "\"Action\":\"sts:AssumeRoleWithWebIdentity\","
                + "\"Condition\":{\"StringLike\":{\"token.actions.githubusercontent.com:sub\":\"repo:acme/*\"}}}]}";
        IamRole role = iamService.createRole("CI", "/", trust, null, 0, null);
        roleArn = role.getArn();

        WebIdentityTokenValidator validator = new WebIdentityTokenValidator(config, mapper);
        WebIdentityTrustEvaluator trustEvaluator = new WebIdentityTrustEvaluator(iamService, mapper);
        handler = new StsQueryHandler(iamService, accountResolver, regionResolver, config, validator, trustEvaluator);
    }

    @Test
    void flagOffAcceptsAnyTokenWithStubbedClaims() {
        when(webIdentityCfg.enabled()).thenReturn(false);

        Response response = handler.handle("AssumeRoleWithWebIdentity",
                params(roleArn, "session", "garbage-not-a-jwt"));

        assertEquals(200, response.getStatus());
        String xml = (String) response.getEntity();
        assertTrue(xml.contains("<SubjectFromWebIdentityToken>web-identity-subject</SubjectFromWebIdentityToken>"), xml);
        assertTrue(xml.contains("<Provider>accounts.google.com</Provider>"), xml);
        assertTrue(xml.contains("<Audience>sts.amazonaws.com</Audience>"), xml);
        assertTrue(xml.contains("<AccessKeyId>ASIA"), xml);
        assertTrue(xml.contains("<Arn>arn:aws:sts::000000000000:assumed-role/CI/session</Arn>"), xml);
    }

    @Test
    void flagOnValidTokenReturnsRealClaims() {
        when(webIdentityCfg.enabled()).thenReturn(true);
        long now = System.currentTimeMillis() / 1000L;
        String token = sign(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"k1\"}",
                "{\"iss\":\"" + ISSUER + "\",\"sub\":\"repo:acme/widgets:ref:refs/heads/main\","
                        + "\"aud\":\"sts.amazonaws.com\",\"exp\":" + (now + 3600) + ",\"iat\":" + now + "}",
                keyPair.getPrivate());

        Response response = handler.handle("AssumeRoleWithWebIdentity", params(roleArn, "session", token));

        assertEquals(200, response.getStatus());
        String xml = (String) response.getEntity();
        assertTrue(xml.contains("<SubjectFromWebIdentityToken>repo:acme/widgets:ref:refs/heads/main</SubjectFromWebIdentityToken>"),
                xml);
        assertTrue(xml.contains("<Provider>" + ISSUER + "</Provider>"), xml);
        assertTrue(xml.contains("<Audience>sts.amazonaws.com</Audience>"), xml);
        assertTrue(xml.contains("<AccessKeyId>ASIA"), xml);
        assertTrue(xml.contains("<AssumedRoleId>AROA"), xml);
        assertTrue(xml.contains("<Arn>arn:aws:sts::000000000000:assumed-role/CI/session</Arn>"), xml);
    }

    @Test
    void flagOnInvalidTokenRejected() {
        when(webIdentityCfg.enabled()).thenReturn(true);

        Response response = handler.handle("AssumeRoleWithWebIdentity",
                params(roleArn, "session", "garbage-not-a-jwt"));

        assertEquals(400, response.getStatus());
        String xml = (String) response.getEntity();
        assertTrue(xml.contains("<Code>InvalidIdentityToken</Code>"), xml);
    }

    @Test
    void flagOnValidTokenButTrustConditionDeniesReturnsAccessDenied() {
        when(webIdentityCfg.enabled()).thenReturn(true);
        long now = System.currentTimeMillis() / 1000L;
        // sub does not match the role trust policy's repo:acme/* condition
        String token = sign(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"k1\"}",
                "{\"iss\":\"" + ISSUER + "\",\"sub\":\"repo:evil/fork:ref\","
                        + "\"aud\":\"sts.amazonaws.com\",\"exp\":" + (now + 3600) + "}",
                keyPair.getPrivate());

        Response response = handler.handle("AssumeRoleWithWebIdentity", params(roleArn, "session", token));

        assertEquals(403, response.getStatus());
        String xml = (String) response.getEntity();
        assertTrue(xml.contains("<Code>AccessDenied</Code>"), xml);
    }

    @Test
    void flagOnExpiredTokenReturnsExpiredException() {
        when(webIdentityCfg.enabled()).thenReturn(true);
        long now = System.currentTimeMillis() / 1000L;
        String token = sign(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"k1\"}",
                "{\"iss\":\"" + ISSUER + "\",\"sub\":\"repo:acme/widgets:ref\","
                        + "\"aud\":\"sts.amazonaws.com\",\"exp\":" + (now - 3600) + "}",
                keyPair.getPrivate());

        Response response = handler.handle("AssumeRoleWithWebIdentity", params(roleArn, "session", token));

        assertEquals(400, response.getStatus());
        String xml = (String) response.getEntity();
        assertTrue(xml.contains("<Code>ExpiredTokenException</Code>"), xml);
    }

    @Test
    void flagOnValidTokenWithoutAudOmitsAudience() {
        when(webIdentityCfg.enabled()).thenReturn(true);
        long now = System.currentTimeMillis() / 1000L;
        // Provider configures no expected audience, so a token without aud still validates; the
        // response must omit <Audience> rather than fabricate the stub default.
        String token = sign(
                "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"k1\"}",
                "{\"iss\":\"" + ISSUER + "\",\"sub\":\"repo:acme/widgets:ref\",\"exp\":" + (now + 3600) + "}",
                keyPair.getPrivate());

        Response response = handler.handle("AssumeRoleWithWebIdentity", params(roleArn, "session", token));

        assertEquals(200, response.getStatus());
        String xml = (String) response.getEntity();
        assertFalse(xml.contains("<Audience>"), xml);
    }

    // ---- helpers -------------------------------------------------------------

    private static MultivaluedMap<String, String> params(String roleArn, String session, String token) {
        MultivaluedMap<String, String> p = new MultivaluedHashMap<>();
        p.putSingle("RoleArn", roleArn);
        p.putSingle("RoleSessionName", session);
        p.putSingle("WebIdentityToken", token);
        return p;
    }
}
