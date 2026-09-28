# Local dev only. OPA's own API guard (--authorization=basic), loaded by the opal-client's inline OPA
# at startup: every call needs the policy-store bearer token (jinbe's OPA_TOKEN), as in the cluster.
package system.authz

import rego.v1

default allow := false

# Liveness only; it reveals nothing.
allow if input.path == ["health"]

allow if {
	token := opa.runtime().env.OPAL_POLICY_STORE_AUTH_TOKEN
	token != ""
	input.identity == token
}
