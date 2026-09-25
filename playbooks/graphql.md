# Playbook: GraphQL

A single endpoint (usually `/graphql`, `/api/graphql`, `/v1/graphql`) that speaks
its own query language. The attack surface differs from REST: one endpoint, many
operations, and introspection often leaks the entire schema.

## Recon
1. **Confirm it's GraphQL:** POST `{"query":"{__typename}"}`; a `{"data":{"__typename":"Query"}}`
   reply confirms it.
2. **Introspection** (the map of everything):
   ```
   {"query":"{__schema{types{name fields{name args{name}}}}}"}
   ```
   Full query = the standard introspection query. If it works, you have every
   type, field, query and mutation — dump it, save to worklog. If introspection
   is disabled, use suggestions ("Did you mean ...") to brute field names, or
   fingerprint the engine (Apollo/Hasura/graphql-yoga) with clientjs/graphw00f
   patterns.

## Attacks
- **Broken authorization** (the big one): call mutations/queries a role shouldn't
  reach (`deleteUser`, `updateRole`, `users{email}`), or IDOR via node IDs. Same
  logic as the access-control playbook, different transport.
- **Excessive data:** ask for fields the UI never shows (`passwordHash`, internal
  flags, other users' PII) — the resolver may not filter.
- **Batching / alias abuse:** send many aliased operations in one request to
  bypass rate limits or brute-force (e.g. 100 aliased `login` attempts in one POST).
- **Injection through resolvers:** args flow into SQL/NoSQL/OS — test SQLi/NoSQLi
  in GraphQL arguments just like any other input.
- **DoS via deep nesting / circular queries:** note as a risk; don't fire it at a
  live target.

## Report
Introspection dump + the specific unauthorized operation that returned data it
shouldn't. Remediation: disable introspection in prod, enforce field/object-level
authz in resolvers, query depth/cost limits, disable or auth-gate batching.
