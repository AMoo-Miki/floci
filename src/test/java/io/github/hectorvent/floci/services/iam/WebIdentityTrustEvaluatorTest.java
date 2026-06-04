package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.github.hectorvent.floci.services.iam.webidentity.WebIdentityClaims;
import io.github.hectorvent.floci.services.iam.webidentity.WebIdentityTrustEvaluator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static io.github.hectorvent.floci.services.iam.webidentity.WebIdentityTrustEvaluator.Decision.ALLOW;
import static io.github.hectorvent.floci.services.iam.webidentity.WebIdentityTrustEvaluator.Decision.DENY;
import static org.junit.jupiter.api.Assertions.assertEquals;

class WebIdentityTrustEvaluatorTest {

    private static final String ISSUER = "https://token.actions.githubusercontent.com";

    private IamService iamService;
    private WebIdentityTrustEvaluator evaluator;

    @BeforeEach
    void setUp() {
        iamService = new IamService(
                new InMemoryStorage<>(), new InMemoryStorage<>(), new InMemoryStorage<>(),
                new InMemoryStorage<>(), new InMemoryStorage<>(), new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                new RegionResolver("us-east-1", "000000000000"));
        evaluator = new WebIdentityTrustEvaluator(iamService, new ObjectMapper());
    }

    private static final String FED =
            "\"Principal\":{\"Federated\":\"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com\"}";

    private WebIdentityClaims claims(String sub, String aud) {
        return new WebIdentityClaims(ISSUER, sub, List.of(aud));
    }

    /** Wraps a single statement body (the inner JSON of one statement) in a policy document. */
    private String policy(String statementInner) {
        return "{\"Version\":\"2012-10-17\",\"Statement\":[{" + statementInner + "}]}";
    }

    private String trustPolicy(String subPattern) {
        return "{\"Version\":\"2012-10-17\",\"Statement\":[{"
                + "\"Effect\":\"Allow\","
                + "\"Principal\":{\"Federated\":\"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com\"},"
                + "\"Action\":\"sts:AssumeRoleWithWebIdentity\","
                + "\"Condition\":{"
                + "\"StringEquals\":{\"token.actions.githubusercontent.com:aud\":\"sts.amazonaws.com\"},"
                + "\"StringLike\":{\"token.actions.githubusercontent.com:sub\":\"" + subPattern + "\"}"
                + "}}]}";
    }

    @Test
    void allowsWhenSubAndAudMatch() {
        IamRole role = iamService.createRole("CI", "/", trustPolicy("repo:acme/widgets:*"), null, 0, null);
        var decision = evaluator.evaluate(role.getArn(),
                claims("repo:acme/widgets:ref:refs/heads/main", "sts.amazonaws.com"));
        assertEquals(WebIdentityTrustEvaluator.Decision.ALLOW, decision);
    }

    @Test
    void deniesWhenSubDoesNotMatchCondition() {
        IamRole role = iamService.createRole("CI", "/", trustPolicy("repo:acme/widgets:*"), null, 0, null);
        var decision = evaluator.evaluate(role.getArn(),
                claims("repo:evil/fork:ref:refs/heads/main", "sts.amazonaws.com"));
        assertEquals(WebIdentityTrustEvaluator.Decision.DENY, decision);
    }

    @Test
    void deniesWhenAudienceDoesNotMatchCondition() {
        IamRole role = iamService.createRole("CI", "/", trustPolicy("repo:acme/widgets:*"), null, 0, null);
        var decision = evaluator.evaluate(role.getArn(),
                claims("repo:acme/widgets:ref:refs/heads/main", "wrong-audience"));
        assertEquals(WebIdentityTrustEvaluator.Decision.DENY, decision);
    }

    @Test
    void deniesWhenRoleNotFound() {
        var decision = evaluator.evaluate("arn:aws:iam::000000000000:role/DoesNotExist",
                claims("repo:acme/widgets:ref", "sts.amazonaws.com"));
        assertEquals(WebIdentityTrustEvaluator.Decision.DENY, decision);
    }

    @Test
    void allowsWhenStatementHasNoCondition() {
        String trust = "{\"Version\":\"2012-10-17\",\"Statement\":[{"
                + "\"Effect\":\"Allow\","
                + "\"Principal\":{\"Federated\":\"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com\"},"
                + "\"Action\":\"sts:AssumeRoleWithWebIdentity\"}]}";
        IamRole role = iamService.createRole("Open", "/", trust, null, 0, null);
        var decision = evaluator.evaluate(role.getArn(), claims("anything", "any-aud"));
        assertEquals(WebIdentityTrustEvaluator.Decision.ALLOW, decision);
    }

    @Test
    void explicitDenyWins() {
        String fed = "\"Principal\":{\"Federated\":\"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com\"},";
        String trust = "{\"Version\":\"2012-10-17\",\"Statement\":["
                + "{\"Effect\":\"Allow\"," + fed + "\"Action\":\"sts:AssumeRoleWithWebIdentity\"},"
                + "{\"Effect\":\"Deny\"," + fed + "\"Action\":\"sts:AssumeRoleWithWebIdentity\","
                + "\"Condition\":{\"StringLike\":{\"token.actions.githubusercontent.com:sub\":\"repo:acme/*\"}}}"
                + "]}";
        IamRole role = iamService.createRole("Mixed", "/", trust, null, 0, null);
        var decision = evaluator.evaluate(role.getArn(),
                claims("repo:acme/widgets:ref", "sts.amazonaws.com"));
        assertEquals(WebIdentityTrustEvaluator.Decision.DENY, decision);
    }

    @Test
    void stringLikeIsCaseSensitive() {
        // AWS StringLike is case-sensitive: repo:ACME/* must NOT match repo:acme/...
        IamRole role = iamService.createRole("Case", "/", trustPolicy("repo:ACME/*"), null, 0, null);
        assertEquals(DENY, evaluator.evaluate(role.getArn(),
                claims("repo:acme/widgets:ref", "sts.amazonaws.com")));
    }

    @Test
    void multiAudMatchesConditionOnAnyValue() {
        // The :aud condition is evaluated against the full audience list, so a match on any value
        // (regardless of order) satisfies it.
        IamRole role = iamService.createRole("CI", "/", trustPolicy("repo:acme/widgets:*"), null, 0, null);
        var multiAud = new WebIdentityClaims(ISSUER, "repo:acme/widgets:ref",
                List.of("other", "sts.amazonaws.com"));
        assertEquals(ALLOW, evaluator.evaluate(role.getArn(), multiAud));
    }

    @Test
    void stsWildcardActionAllows() {
        IamRole role = iamService.createRole("Star", "/",
                policy("\"Effect\":\"Allow\"," + FED + ",\"Action\":\"sts:*\""), null, 0, null);
        assertEquals(ALLOW, evaluator.evaluate(role.getArn(), claims("any", "any")));
    }

    @Test
    void bareWildcardActionAllows() {
        IamRole role = iamService.createRole("Bare", "/",
                policy("\"Effect\":\"Allow\"," + FED + ",\"Action\":\"*\""), null, 0, null);
        assertEquals(ALLOW, evaluator.evaluate(role.getArn(), claims("any", "any")));
    }

    @Test
    void nonMatchingActionDenies() {
        IamRole role = iamService.createRole("Other", "/",
                policy("\"Effect\":\"Allow\"," + FED + ",\"Action\":\"sts:AssumeRole\""), null, 0, null);
        assertEquals(DENY, evaluator.evaluate(role.getArn(), claims("any", "any")));
    }

    @Test
    void denyViaNotActionWins() {
        // A Deny whose NotAction does not list the web-identity action applies to it → DENY.
        String trust = "{\"Version\":\"2012-10-17\",\"Statement\":["
                + "{\"Effect\":\"Allow\"," + FED + ",\"Action\":\"sts:AssumeRoleWithWebIdentity\"},"
                + "{\"Effect\":\"Deny\"," + FED + ",\"NotAction\":\"s3:GetObject\"}"
                + "]}";
        IamRole role = iamService.createRole("NotAction", "/", trust, null, 0, null);
        assertEquals(DENY, evaluator.evaluate(role.getArn(), claims("any", "any")));
    }

    @Test
    void deniesStatementWithoutFederatedPrincipal() {
        // No Principal{Federated} → the statement does not bind to the issuer → DENY.
        String trust = "{\"Version\":\"2012-10-17\",\"Statement\":[{"
                + "\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRoleWithWebIdentity\"}]}";
        IamRole role = iamService.createRole("NoPrincipal", "/", trust, null, 0, null);
        assertEquals(DENY, evaluator.evaluate(role.getArn(), claims("any", "any")));
    }

    @Test
    void deniesCrossIssuerPrincipal() {
        // Principal names a different OIDC provider than the token's issuer → DENY.
        String trust = "{\"Version\":\"2012-10-17\",\"Statement\":[{"
                + "\"Effect\":\"Allow\","
                + "\"Principal\":{\"Federated\":\"arn:aws:iam::000000000000:oidc-provider/accounts.google.com\"},"
                + "\"Action\":\"sts:AssumeRoleWithWebIdentity\"}]}";
        IamRole role = iamService.createRole("CrossIssuer", "/", trust, null, 0, null);
        assertEquals(DENY, evaluator.evaluate(role.getArn(), claims("any", "any")));
    }

    @Test
    void nonObjectConditionDenies() {
        // A Condition that is present but not an object is malformed → fail closed.
        IamRole role = iamService.createRole("BadCond", "/",
                policy("\"Effect\":\"Allow\"," + FED
                        + ",\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Condition\":\"nonsense\""),
                null, 0, null);
        assertEquals(DENY, evaluator.evaluate(role.getArn(), claims("any", "any")));
    }

    @Test
    void malformedEffectDenies() {
        // Effect must be exactly Allow/Deny; a typo'd effect contributes no allow → DENY.
        IamRole role = iamService.createRole("BadEffect", "/",
                policy("\"Effect\":\"Allowed\"," + FED + ",\"Action\":\"sts:AssumeRoleWithWebIdentity\""),
                null, 0, null);
        assertEquals(DENY, evaluator.evaluate(role.getArn(), claims("any", "any")));
    }

    @Test
    void unsupportedOperatorFailsClosed() {
        IamRole role = iamService.createRole("BadOp", "/",
                policy("\"Effect\":\"Allow\"," + FED + ",\"Action\":\"sts:AssumeRoleWithWebIdentity\","
                        + "\"Condition\":{\"DateGreaterThan\":{\"token.actions.githubusercontent.com:sub\":\"2020-01-01T00:00:00Z\"}}"),
                null, 0, null);
        assertEquals(DENY, evaluator.evaluate(role.getArn(), claims("repo:acme/x", "sts.amazonaws.com")));
    }

    @Test
    void stringNotLikeDeniesWhenSubMatchesPattern() {
        // StringNotLike requires the value NOT to match; a sub that matches the pattern → DENY.
        IamRole role = iamService.createRole("NotLike", "/",
                policy("\"Effect\":\"Allow\"," + FED + ",\"Action\":\"sts:AssumeRoleWithWebIdentity\","
                        + "\"Condition\":{\"StringNotLike\":{\"token.actions.githubusercontent.com:sub\":\"repo:acme/*\"}}"),
                null, 0, null);
        assertEquals(DENY, evaluator.evaluate(role.getArn(),
                claims("repo:acme/widgets:ref", "sts.amazonaws.com")));
    }

    @Test
    void ifExistsPassesWhenClaimAbsent() {
        // StringEqualsIfExists on :aud with a token that carries no aud → the key passes.
        IamRole role = iamService.createRole("IfExists", "/",
                policy("\"Effect\":\"Allow\"," + FED + ",\"Action\":\"sts:AssumeRoleWithWebIdentity\","
                        + "\"Condition\":{\"StringEqualsIfExists\":{\"token.actions.githubusercontent.com:aud\":\"sts.amazonaws.com\"}}"),
                null, 0, null);
        var noAud = new WebIdentityClaims(ISSUER, "repo:acme/x", List.of());
        assertEquals(ALLOW, evaluator.evaluate(role.getArn(), noAud));
    }

    @Test
    void emptyStatementDenies() {
        IamRole role = iamService.createRole("Empty", "/",
                "{\"Version\":\"2012-10-17\",\"Statement\":[]}", null, 0, null);
        assertEquals(DENY, evaluator.evaluate(role.getArn(), claims("any", "any")));
    }

    @Test
    void unparseableTrustDocDenies() {
        IamRole role = iamService.createRole("Garbage", "/", "this is not json", null, 0, null);
        assertEquals(DENY, evaluator.evaluate(role.getArn(), claims("any", "any")));
    }
}
