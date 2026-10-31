# PS033 lab profile v0.1

## Pin and scope

Pin `draft-mozleywilliams-dnsop-dnsaid-02` (27 May 2026), particularly sections
3.1 and 6. This is an individual Internet-Draft, not an adopted IETF standard.
The project is a DNS-AID-style subset, with local choices documented below.
The organizer has not supplied a specific revision; this pin is our proposal
for mentor review, not a claim of organizer approval.

The client knows three logical owner names under `diag.test.`. It discovers
their current connection parameters through SVCB queries. Knowing a service's
logical name does not mean hardcoding its endpoint IP or port in the client.
The DNS server address and trust anchor are bootstrap configuration.

## Wire data

Example unsigned presentation of a record subsequently signed by the publisher:

```text
latency.diag.test. 30 IN SVCB 1 . (
  mandatory=alpn,port,key65280,key65281
  alpn="http/1.1"
  port=18443
  key65280="latency"
  key65281="/invoke"
)
latency.diag.test. 30 IN A 127.0.0.1
```

Standard fields: priority 1 is ServiceMode; target `.` uses the owner name;
`alpn` selects HTTP/1.1; `port` supplies the service port; `mandatory` makes
unsupported required parameters a rejection rather than a silent downgrade.

**Local profile choices, not registered DNS-AID parameter numbers:**

- Private-use key 65280 contains an ASCII inline capability identifier, one of
  `latency`, `traceroute`, or `health`. This models the draft's `cap` concept.
- Private-use key 65281 contains the operation path `/invoke`. This is our local
  invocation-path extension. It is not the draft's `well-known` descriptor path.
- No capability descriptor is fetched; consequently `cap-sha256` is not used.
- Mock API: HTTPS POST to `/invoke`, no request body, JSON response.
- TLS certificate verification uses a local trust file independent of DNSSEC.
- Random bearer credentials are service-specific and provisioned out of band.
  Bearer tokens and private keys never appear in DNS responses or Git.

All three services use the same small transport profile and separate listeners.
There is no AI model or LLM dependency. The draft's agent discovery mechanism
is applied to diagnostic services as requested in PS-033.

## Validation order

1. Query the known service owner for SVCB with DNSSEC data requested.
2. Match the requested owner and record type; require an RRSIG.
3. Validate the RRset with the locally provisioned zone public key, including
   signature validity time. Never accept a DNSKEY learned from the answer as
   a new trust anchor. Never treat an AD flag alone as proof.
4. Require exactly one supported ServiceMode record; check mandatory keys,
   capability, transport, invocation path, target hostname, and permitted port.
5. Query its A record and validate that signature too. The current local policy
   only allows the loopback address and the expected service hostname.
6. Connect to that validated address using the discovered port. Validate the TLS
   certificate against the independent TLS trust file and expected DNS hostname.
7. Send the separately provisioned service token. The service independently
   authenticates it before performing its single permitted mock operation.
8. Return the result or a stage-specific error. Never fall back to unsigned DNS
   or disable TLS verification after a failure.

There is no application DNS cache; each invocation queries again. TTL-aware
caching must also respect signature expiration when added later.

## Negative tests and their meaning

- **Bogus:** change a signed SVCB record without re-signing. DNSSEC must reject.
- **Malformed:** publish and correctly sign a record with a capability outside
  the local schema. DNSSEC passes; metadata validation must reject separately.
- **Unavailable:** publish valid metadata while the service listener is absent.
  DNSSEC and metadata checks pass; connection fails without hanging.
- **Unauthorized:** use valid metadata and TLS with an incorrect bearer token.
  The service must return 401; discovery must not bypass authentication.
- **Expired:** cryptographic signatures have expired; invocation is blocked.
- **Unsigned:** omit RRSIG from the response; invocation is blocked.
- Further integration coverage: wrong provisioned key, address-record tampering,
  unknown mandatory parameter, three successful services, DNS TCP transport,
  a token belonging to another service, and an untrusted TLS certificate.

This deliberately avoids attributing every DNS failure to an attacker. A
transport failure is `DNS_UNAVAILABLE`; a refused question is
`DNS_QUERY_FAILED`; a missing signature is `DNSSEC_UNVERIFIED`; a failed
signature check is `DNSSEC_BOGUS`.

## Out of scope for v0.1

Public-root DS chains, key rollover, secure key distribution across machines,
authenticated denial proofs in the client, organization-index enumeration,
AliasMode, multiple competing SVCB records, IPv6, DANE, public registry search,
descriptor digests, real network probes, and production authorization policies.
The generated zone is signed, but the serving harness is intentionally limited.

## Mentor pseudocode

```text
for each known diagnostic service:
    response = query_DNS(service, SVCB, request_DNSSEC=true)
    require valid_signature(response, provisioned_zone_key, current_time)
    endpoint = parse_and_validate_supported_metadata(response)
    require local_policy_allows(endpoint)
    addresses = query_DNS(endpoint.hostname, A, request_DNSSEC=true)
    require valid_signature(addresses, provisioned_zone_key, current_time)
    require local_policy_allows(addresses)
    connection = connect_TLS(addresses, endpoint.port, expected_hostname)
    require valid_TLS_identity(connection, provisioned_TLS_trust)
    result = invoke(connection, endpoint.path, separately_provisioned_token)
    report result or precise failure_stage
```
