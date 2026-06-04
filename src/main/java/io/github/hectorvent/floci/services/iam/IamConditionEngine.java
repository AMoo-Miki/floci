package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Shared IAM/trust policy condition mechanics: statement extraction, value-list coercion, and the
 * condition-operator dispatch.
 *
 * <p>Both {@link IamPolicyEvaluator} (permission boundary) and
 * {@code WebIdentityTrustEvaluator} (trust boundary) route operator matching here so the operator
 * semantics cannot drift. Each caller keeps its own statement/action/principal selection and the
 * block-level AND/OR + IfExists handling that differs between the two boundaries, and supplies its
 * own {@link GlobMatcher}: IAM permission checks are case-folding for backward compatibility, while
 * the web-identity trust boundary is case-sensitive to match AWS {@code StringLike}.
 */
public final class IamConditionEngine {

    private static final Logger LOG = Logger.getLogger(IamConditionEngine.class);

    private IamConditionEngine() {}

    /** Glob matcher used for {@code StringLike}/{@code StringNotLike}/{@code Arn*} operators. */
    @FunctionalInterface
    public interface GlobMatcher {
        boolean matches(String pattern, String value);
    }

    /** Extracts the statement nodes from a policy/trust document root (array or single object). */
    public static List<JsonNode> statementNodes(JsonNode root) {
        List<JsonNode> result = new ArrayList<>();
        if (root == null) {
            return result;
        }
        JsonNode stmt = root.path("Statement");
        if (stmt.isArray()) {
            stmt.forEach(result::add);
        } else if (stmt.isObject()) {
            result.add(stmt);
        }
        return result;
    }

    /** Coerces a textual-or-array JSON node into a list of strings ({@code null} → empty list). */
    public static List<String> nodeToList(JsonNode node) {
        List<String> list = new ArrayList<>();
        if (node == null) {
            return list;
        }
        if (node.isTextual()) {
            list.add(node.asText());
        } else if (node.isArray()) {
            node.forEach(n -> list.add(n.asText()));
        }
        return list;
    }

    /**
     * Evaluates a single condition operator against one {@code (ctxValue, condValue)} pair.
     * The {@code IfExists} suffix and key presence are handled by the caller; this method dispatches
     * only the comparison. Unknown operators fail closed (no match). The {@code Null} operator is
     * intentionally absent — it depends on key presence and is handled in the caller's block logic.
     */
    public static boolean evaluateOperator(String operator, String ctxValue, String condValue,
                                           GlobMatcher glob) {
        return switch (operator) {
            case "StringEquals"              -> ctxValue.equals(condValue);
            case "StringNotEquals"           -> !ctxValue.equals(condValue);
            case "StringEqualsIgnoreCase"    -> ctxValue.equalsIgnoreCase(condValue);
            case "StringNotEqualsIgnoreCase" -> !ctxValue.equalsIgnoreCase(condValue);
            case "StringLike"                -> glob.matches(condValue, ctxValue);
            case "StringNotLike"             -> !glob.matches(condValue, ctxValue);
            case "ArnEquals", "ArnLike"      -> glob.matches(condValue, ctxValue);
            case "ArnNotEquals", "ArnNotLike"-> !glob.matches(condValue, ctxValue);
            case "Bool"                      -> Boolean.parseBoolean(condValue) == Boolean.parseBoolean(ctxValue);
            case "NumericEquals"             -> compareNumeric(ctxValue, condValue) == 0;
            case "NumericNotEquals"          -> compareNumeric(ctxValue, condValue) != 0;
            case "NumericLessThan"           -> compareNumeric(ctxValue, condValue) < 0;
            case "NumericLessThanEquals"     -> compareNumeric(ctxValue, condValue) <= 0;
            case "NumericGreaterThan"        -> compareNumeric(ctxValue, condValue) > 0;
            case "NumericGreaterThanEquals"  -> compareNumeric(ctxValue, condValue) >= 0;
            case "DateEquals"                -> compareDates(ctxValue, condValue) == 0;
            case "DateNotEquals"             -> compareDates(ctxValue, condValue) != 0;
            case "DateLessThan"              -> compareDates(ctxValue, condValue) < 0;
            case "DateLessThanEquals"        -> compareDates(ctxValue, condValue) <= 0;
            case "DateGreaterThan"           -> compareDates(ctxValue, condValue) > 0;
            case "DateGreaterThanEquals"     -> compareDates(ctxValue, condValue) >= 0;
            case "IpAddress"                 -> matchesIpAddress(condValue, ctxValue);
            case "NotIpAddress"              -> !matchesIpAddress(condValue, ctxValue);
            default -> {
                LOG.warnv("Unsupported condition operator: {0} — treating as no-match", operator);
                yield false;
            }
        };
    }

    private static int compareNumeric(String ctxValue, String condValue) {
        try {
            return Double.compare(Double.parseDouble(ctxValue), Double.parseDouble(condValue));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static int compareDates(String ctxValue, String condValue) {
        try {
            return Instant.parse(ctxValue).compareTo(Instant.parse(condValue));
        } catch (Exception e) {
            return 0;
        }
    }

    private static boolean matchesIpAddress(String condValue, String ctxValue) {
        if (condValue.contains("/")) {
            return matchesCidr(condValue, ctxValue);
        }
        return condValue.equals(ctxValue);
    }

    private static boolean matchesCidr(String cidr, String ip) {
        try {
            String[] parts = cidr.split("/");
            int prefix = Integer.parseInt(parts[1]);
            long cidrAddr = ipToLong(parts[0]);
            long ipAddr = ipToLong(ip);
            long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
            return (cidrAddr & mask) == (ipAddr & mask);
        } catch (Exception e) {
            return false;
        }
    }

    private static long ipToLong(String ip) {
        String[] octets = ip.split("\\.");
        long result = 0;
        for (String octet : octets) {
            result = (result << 8) | Integer.parseInt(octet);
        }
        return result;
    }
}
