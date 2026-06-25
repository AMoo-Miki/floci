# STS

**Protocol:** Query (XML) — `POST http://localhost:4566/` with `Action=` parameter

## Supported Actions

| Action | Description |
|---|---|
| `GetCallerIdentity` | Returns the account ID, user ID, and ARN |
| `AssumeRole` | Assume an IAM role, returns temporary credentials |
| `AssumeRoleWithWebIdentity` | Assume a role using a web identity token (OIDC) |
| `AssumeRoleWithSAML` | Assume a role using a SAML assertion |
| `GetSessionToken` | Get temporary credentials for an IAM user |
| `GetFederationToken` | Get temporary credentials for a federated user |
| `DecodeAuthorizationMessage` | Decode an encoded authorization failure message |

## Configuration

| Variable | Default | Description |
|---|---|---|
| `FLOCI_SERVICES_STS_ENABLED` | `true` | Enable or disable the service |
| `FLOCI_SERVICES_IAM_WEB_IDENTITY_ENABLED` | `false` | Validate web-identity tokens and trust-policy conditions on `sts:AssumeRoleWithWebIdentity` (see below) |
| `FLOCI_SERVICES_IAM_WEB_IDENTITY_CLOCK_SKEW_SECONDS` | `60` | Allowed clock skew when checking `exp`/`nbf`/`iat` |

## Web-identity token validation

By default (`web-identity.enabled = false`), `AssumeRoleWithWebIdentity` accepts any non-blank
token and returns stubbed claims (`Provider=accounts.google.com`,
`SubjectFromWebIdentityToken=web-identity-subject`, `Audience=sts.amazonaws.com`). This keeps
zero-config local development frictionless but does not exercise the trust boundary (who is
allowed to assume the role).

When enabled, Floci validates the web-identity JWT entirely offline against statically configured
issuer keys — no network egress to the OIDC provider:

1. Verifies the RS256 signature against the issuer's configured JWKS, preferring the key whose
   `kid` matches the token header and falling back to any of that issuer's configured keys. Only
   RS256 signing keys with a 2048–8192-bit modulus are accepted.
2. Checks `iss` (must be a registered issuer); requires `exp` and checks it — a token that omits
   `exp` or carries a non-numeric `exp` is rejected — and checks `nbf`/`iat` when present, all
   within the configured skew; checks `aud` only when the provider configures an expected audience.
3. Decodes the real `sub` and returns the real `iss`/`sub`/`aud` in the response.
4. Binds the role to the token's issuer and evaluates its trust policy before minting credentials:
   a statement applies only when its `Principal.Federated` names the OIDC provider for the token's
   `iss`, and its `Condition` matches the decoded claims. Supported condition keys are
   `<issuer>:sub` and `<issuer>:aud` (the issuer with its scheme stripped, matching AWS naming);
   `<issuer>:aud` is matched against every audience the token carries. Supported operators are
   `StringEquals`, `StringEqualsIgnoreCase`, `StringLike` and their negations (`StringLike` is
   case-sensitive, matching AWS); other operators and the `ForAnyValue:`/`ForAllValues:`
   qualifiers fail closed.

On failure, Floci returns the AWS-equivalent error: `ExpiredTokenException` (expired token),
`InvalidIdentityToken` (malformed/unverifiable token, unknown issuer, audience mismatch), or
`AccessDenied` (the trust-policy `Condition` did not match the token claims).

Issuers and their signing keys are registered statically (cleaner in YAML than via environment
variables). Each provider points at a JWKS document via a file path:

```yaml
floci:
  services:
    iam:
      web-identity:
        enabled: true
        clock-skew-seconds: 60
        providers:
          - issuer: https://token.actions.githubusercontent.com
            audience: sts.amazonaws.com          # optional; enforced only when set
            jwks-path: /etc/floci/github-jwks.json
          - issuer: https://accounts.google.com
            jwks-path: /etc/floci/google-jwks.json
```

Only RS256 keys are supported (covers Google, GitHub Actions, Cognito, CircleCI, and OCI). The
OIDC provider registry (`CreateOpenIDConnectProvider`) is not modelled; instead the role's
`Principal.Federated` is matched directly against the token's issuer host (its
`oidc-provider/<host>` segment must equal the `iss` host), and the trust boundary is then
exercised through the `Condition` keys above.

### Startup and readiness

When validation is enabled, the configured JWKS are loaded **eagerly at startup** rather than
lazily on the first `AssumeRoleWithWebIdentity`, and startup **fails closed**: if a configured
provider has no readable JWKS or no usable RS256 key, Floci logs the offending issuer(s) and
aborts boot instead of starting in a state that would reject those tokens at runtime. This
removes the cold-start window where the first assume blocked on (or raced) lazy key loading.

Because loading happens during startup, readiness is deterministic: once Floci reports ready via
`GET /_floci/init` (`completed.ready = true`), the validator is built and every configured issuer
is loaded. Gate dependent services on `/_floci/init` readiness — not `/_floci/health`, which is a
liveness/info endpoint that returns `200` as soon as the process is up, before init completes.

Note that web-identity validation is the *trust* boundary only. Whether the assumed role itself
exists is a separate concern: IAM roles are created by your own seeding (`CreateRole` /
`PutRolePolicy`) and are stored per account, so an `AssumeRoleWithWebIdentity` for a role that has
not been created yet (or was created under a different account) returns `AccessDenied` from the
trust evaluation — order your role seeding before the first assume.

## Examples

```bash
export AWS_ENDPOINT_URL=http://localhost:4566

# Get caller identity (always works, useful for smoke testing)
aws sts get-caller-identity --endpoint-url $AWS_ENDPOINT_URL

# Assume a role
aws sts assume-role \
  --role-arn arn:aws:iam::000000000000:role/my-role \
  --role-session-name dev-session \
  --endpoint-url $AWS_ENDPOINT_URL

# Get a session token
aws sts get-session-token --endpoint-url $AWS_ENDPOINT_URL
```

`GetCallerIdentity` is commonly used in CI pipelines and integration tests as a quick connectivity check before running more complex tests.

When `FLOCI_SERVICES_IAM_SEED_DEPLOYER_PRINCIPAL=true`, requests signed with the seeded `floci` access key return `arn:aws:iam::000000000000:user/floci-deployer`. Other unknown local credentials continue to return the account root ARN for backward compatibility.
