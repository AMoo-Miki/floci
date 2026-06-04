package io.github.hectorvent.floci.services.iam.webidentity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.iam.IamConditionEngine;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Evaluates a role's trust policy ({@code AssumeRolePolicyDocument}) against the decoded
 * claims of a verified web-identity token, deciding whether the token is allowed to assume
 * the role.
 *
 * <p>This is the trust boundary (who may assume the role), distinct from the permission
 * boundary (what the assumed role may do) already enforced by the IAM enforcement filter.
 *
 * <p>Scope (minimum to serve web-identity Condition checks):
 * <ul>
 *   <li>Statements whose {@code Action} includes {@code sts:AssumeRoleWithWebIdentity}
 *       (or {@code sts:*} / {@code *}); {@code NotAction} is honoured so a Deny expressed via
 *       {@code NotAction} is not silently dropped.</li>
 *   <li>{@code Principal.Federated} must name the OIDC provider for the token's {@code iss}
 *       (the {@code oidc-provider/<host>} segment must equal the issuer host). A statement with
 *       no matching federated principal does not apply — this binds the role to a specific issuer
 *       and fails closed, matching AWS, rather than admitting any registered issuer's token.</li>
 *   <li>{@code Condition} keys {@code <issuer>:sub} and {@code <issuer>:aud} (issuer with the
 *       scheme stripped, matching AWS condition-key naming) evaluated against the decoded
 *       {@code sub}/{@code aud}. Operator-written keys carrying a scheme or trailing slash are
 *       normalized so they cannot silently miss.</li>
 *   <li>Operators: {@code StringEquals}, {@code StringEqualsIgnoreCase}, {@code StringLike}
 *       and their negations, with the {@code IfExists} suffix honoured. {@code StringLike} is
 *       case-sensitive, matching AWS (not the case-folding IAM permission matcher). Set-operator
 *       qualifiers ({@code ForAnyValue:}/{@code ForAllValues:}) and any other operator fail
 *       closed rather than being silently downgraded to a scalar match. The OIDC provider
 *       registry ({@code CreateOpenIDConnectProvider}) is not modelled; the federated principal
 *       is matched against the token's issuer host directly.</li>
 * </ul>
 */
@ApplicationScoped
public class WebIdentityTrustEvaluator {

    private static final Logger LOG = Logger.getLogger(WebIdentityTrustEvaluator.class);

    // Kept distinct from IamPolicyEvaluator.Decision: the trust boundary (who may assume) and the
    // permission boundary (what the assumed role may do) are separate concerns that may evolve apart.
    public enum Decision { ALLOW, DENY }

    private static final String WEB_IDENTITY_ACTION = "sts:assumerolewithwebidentity";
    private static final String OIDC_PROVIDER_MARKER = "oidc-provider/";

    /**
     * String operators meaningful on the {@code sub}/{@code aud} trust boundary. Numeric/Date/Bool/
     * Ip operators and set-operator qualifiers ({@code ForAnyValue:}/{@code ForAllValues:}) are
     * deliberately excluded so they fail closed rather than risk a spurious match on a string claim.
     */
    private static final Set<String> SUPPORTED_OPERATORS = Set.of(
            "StringEquals", "StringNotEquals",
            "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase",
            "StringLike", "StringNotLike");

    private final IamService iamService;
    private final ObjectMapper mapper;

    @Inject
    public WebIdentityTrustEvaluator(IamService iamService, ObjectMapper mapper) {
        this.iamService = iamService;
        this.mapper = mapper;
    }

    /**
     * @param roleArn the role being assumed
     * @param claims  the verified token claims
     * @return {@link Decision#ALLOW} if the trust policy permits this token to assume the role
     */
    public Decision evaluate(String roleArn, WebIdentityClaims claims) {
        String roleName = roleArn != null && roleArn.contains("/")
                ? roleArn.substring(roleArn.lastIndexOf('/') + 1)
                : roleArn;
        Optional<IamRole> roleOpt = roleName == null ? Optional.empty() : iamService.findRole(roleName);
        if (roleOpt.isEmpty()) {
            LOG.debugv("Trust evaluation deny: role {0} not found", roleName);
            return Decision.DENY;
        }
        String trustDoc = roleOpt.get().getAssumeRolePolicyDocument();
        if (trustDoc == null || trustDoc.isBlank()) {
            LOG.debugv("Trust evaluation deny: role {0} has no trust policy", roleName);
            return Decision.DENY;
        }

        Map<String, List<String>> ctx = buildConditionContext(claims);
        String issuerHost = stripScheme(claims.issuer());

        List<JsonNode> statements = parseStatements(trustDoc);
        if (statements.isEmpty()) {
            LOG.debugv("Trust evaluation deny: role {0} has no parseable statements", roleName);
            return Decision.DENY;
        }

        boolean anyAllow = false;
        for (JsonNode stmt : statements) {
            if (!actionMatches(stmt)) {
                continue;
            }
            if (!principalMatches(stmt, issuerHost)) {
                continue;
            }
            if (!conditionMatches(stmt.get("Condition"), ctx)) {
                continue;
            }
            // AWS requires Effect to be exactly "Allow" or "Deny"; anything else (absent,
            // typo, trailing space) is a malformed statement that must fail closed.
            String effect = stmt.path("Effect").asText("");
            if ("Deny".equals(effect)) {
                LOG.debugv("Trust evaluation deny: role {0} matched an explicit Deny", roleName);
                return Decision.DENY; // explicit deny wins
            }
            if ("Allow".equals(effect)) {
                anyAllow = true;
            } else {
                LOG.warnv("Trust statement for role {0} has malformed Effect {1}; treating as non-allow",
                        roleName, effect);
            }
        }
        if (!anyAllow) {
            LOG.debugv("Trust evaluation deny: role {0} has no matching Allow statement "
                    + "(condition mismatch or no issuer-bound statement)", roleName);
        }
        return anyAllow ? Decision.ALLOW : Decision.DENY;
    }

    /**
     * Builds condition-context keys mirroring AWS web-identity naming: the issuer with its
     * scheme and trailing slash stripped, suffixed with {@code :sub} / {@code :aud}. Keys are
     * lowercased to match the trust-policy key normalization. The {@code :aud} key carries the
     * full audience list (not just the first) so authn and authz see the identical multi-valued
     * claim and the decision cannot flip on array ordering.
     */
    private Map<String, List<String>> buildConditionContext(WebIdentityClaims claims) {
        String prefix = stripScheme(claims.issuer());
        Map<String, List<String>> ctx = new HashMap<>();
        if (claims.subject() != null) {
            ctx.put((prefix + ":sub").toLowerCase(), List.of(claims.subject()));
        }
        List<String> audiences = claims.audiences();
        if (audiences != null && !audiences.isEmpty()) {
            ctx.put((prefix + ":aud").toLowerCase(), List.copyOf(audiences));
        }
        return ctx;
    }

    private static String stripScheme(String issuer) {
        if (issuer == null) {
            return "";
        }
        String s = issuer;
        if (s.startsWith("https://")) {
            s = s.substring("https://".length());
        } else if (s.startsWith("http://")) {
            s = s.substring("http://".length());
        }
        if (s.endsWith("/")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    /**
     * A statement applies only if its {@code Principal.Federated} names the OIDC provider for the
     * token's issuer. Absent / non-object Principal, or a Federated value whose
     * {@code oidc-provider/<host>} does not equal the issuer host, fails closed.
     */
    private boolean principalMatches(JsonNode stmt, String issuerHost) {
        JsonNode principal = stmt.get("Principal");
        if (principal == null || !principal.isObject()) {
            return false;
        }
        for (String federated : nodeToList(principal.get("Federated"))) {
            if (federatedMatchesIssuer(federated, issuerHost)) {
                return true;
            }
        }
        return false;
    }

    private boolean federatedMatchesIssuer(String federatedArn, String issuerHost) {
        if (federatedArn == null || issuerHost == null || issuerHost.isEmpty()) {
            return false;
        }
        int idx = federatedArn.indexOf(OIDC_PROVIDER_MARKER);
        String host = idx >= 0 ? federatedArn.substring(idx + OIDC_PROVIDER_MARKER.length()) : federatedArn;
        return stripScheme(host).equalsIgnoreCase(issuerHost);
    }

    /** Action: matches if any Action pattern matches; NotAction: matches if NO pattern matches. */
    private boolean actionMatches(JsonNode stmt) {
        JsonNode actionNode = stmt.get("Action");
        if (actionNode != null) {
            return isWebIdentityAction(nodeToList(actionNode));
        }
        JsonNode notActionNode = stmt.get("NotAction");
        if (notActionNode != null) {
            return !isWebIdentityAction(nodeToList(notActionNode));
        }
        return false;
    }

    private boolean isWebIdentityAction(List<String> actions) {
        for (String a : actions) {
            String lower = a.toLowerCase();
            if (lower.equals(WEB_IDENTITY_ACTION) || lower.equals("sts:*") || lower.equals("*")) {
                return true;
            }
        }
        return false;
    }

    /** AND across condition blocks, AND across keys in a block, OR across a key's values. */
    private boolean conditionMatches(JsonNode conditionNode, Map<String, List<String>> ctx) {
        if (conditionNode == null || conditionNode.isNull()) {
            return true; // no Condition → matches (token verified and issuer-bound)
        }
        if (!conditionNode.isObject()) {
            return false; // present but not an object → malformed → fail closed
        }
        var blocks = conditionNode.fields();
        while (blocks.hasNext()) {
            var block = blocks.next();
            if (!evaluateBlock(block.getKey(), block.getValue(), ctx)) {
                return false;
            }
        }
        return true;
    }

    private boolean evaluateBlock(String rawOperator, JsonNode keyValues, Map<String, List<String>> ctx) {
        String operator = rawOperator;
        boolean ifExists = operator.endsWith("IfExists");
        if (ifExists) {
            operator = operator.substring(0, operator.length() - "IfExists".length());
        }

        var keys = keyValues.fields();
        while (keys.hasNext()) {
            var entry = keys.next();
            String condKey = normalizeConditionKey(entry.getKey());
            List<String> condValues = nodeToList(entry.getValue());
            List<String> ctxValues = ctx.get(condKey);

            if (ctxValues == null || ctxValues.isEmpty()) {
                if (ifExists) {
                    continue; // key absent + IfExists → this key passes
                }
                return false;
            }

            if (!evaluateKey(operator, ctxValues, condValues)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Evaluates one condition key against the (possibly multi-valued) context values via the shared
     * operator dispatch (with the case-sensitive matcher). Positive operators match when any context
     * value matches any condition value; negated operators match only when no context value matches
     * any condition value. Unsupported operators fail closed regardless of negation.
     */
    private boolean evaluateKey(String operator, List<String> ctxValues, List<String> condValues) {
        if (!SUPPORTED_OPERATORS.contains(operator)) {
            LOG.debugv("Unsupported trust-policy condition operator: {0}", operator);
            return false;
        }
        boolean negated = operator.startsWith("StringNot");
        if (negated) {
            // AWS multivalued semantics: matches only if no context value matches any value.
            for (String ctxValue : ctxValues) {
                for (String condValue : condValues) {
                    if (!IamConditionEngine.evaluateOperator(
                            operator, ctxValue, condValue, WebIdentityTrustEvaluator::caseSensitiveGlob)) {
                        return false;
                    }
                }
            }
            return true;
        }
        for (String ctxValue : ctxValues) {
            for (String condValue : condValues) {
                if (IamConditionEngine.evaluateOperator(
                        operator, ctxValue, condValue, WebIdentityTrustEvaluator::caseSensitiveGlob)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Normalizes a trust-policy condition key to match the condition-context naming: lowercased,
     * with any scheme and trailing slash stripped from the issuer portion (the part before the
     * final {@code :sub}/{@code :aud} suffix). This prevents an operator key written as
     * {@code https://issuer:sub} or {@code issuer/:sub} from silently failing to match.
     */
    private static String normalizeConditionKey(String rawKey) {
        String key = rawKey.toLowerCase();
        int lastColon = key.lastIndexOf(':');
        if (lastColon <= 0) {
            return key;
        }
        String issuerPart = key.substring(0, lastColon);
        String suffix = key.substring(lastColon);
        return stripScheme(issuerPart) + suffix;
    }

    /** Case-sensitive glob (AWS StringLike semantics) supporting {@code *} and {@code ?}. */
    static boolean caseSensitiveGlob(String pattern, String value) {
        if (pattern == null || value == null) {
            return false;
        }
        return globHelper(pattern, value, 0, 0);
    }

    private static boolean globHelper(String pat, String val, int pi, int vi) {
        while (pi < pat.length() && vi < val.length()) {
            char p = pat.charAt(pi);
            if (p == '*') {
                while (pi < pat.length() && pat.charAt(pi) == '*') {
                    pi++;
                }
                if (pi == pat.length()) {
                    return true;
                }
                for (int i = vi; i <= val.length(); i++) {
                    if (globHelper(pat, val, pi, i)) {
                        return true;
                    }
                }
                return false;
            } else if (p == '?' || p == val.charAt(vi)) {
                pi++;
                vi++;
            } else {
                return false;
            }
        }
        while (pi < pat.length() && pat.charAt(pi) == '*') {
            pi++;
        }
        return pi == pat.length() && vi == val.length();
    }

    private List<JsonNode> parseStatements(String trustDoc) {
        try {
            return IamConditionEngine.statementNodes(mapper.readTree(trustDoc));
        } catch (Exception e) {
            LOG.debugv("Failed to parse trust policy: {0}", e.getMessage());
            return List.of();
        }
    }

    private List<String> nodeToList(JsonNode node) {
        return IamConditionEngine.nodeToList(node);
    }
}
