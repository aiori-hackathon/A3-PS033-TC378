# A3-PS033-TC378

## DNS-Based Discovery of Diagnostic Services

AIORI-3 Hackathon - PS-033 - Cloud Computing and IoT

**Students:** Chris Itty Biju and Alan Jayan Joseph  
**Faculty mentor:** Revathi BS  
**Institution:** Karunya University of Technology and Sciences

## Proposed solution

We propose a controlled lab that discovers diagnostic service endpoints through
DNS-AID-style metadata. A publisher signs one test zone containing records for
mock latency, traceroute and health services. A client validates the DNS records,
checks the metadata and invokes a service through verified TLS using a separate
service credential.

DNSSEC establishes metadata integrity relative to the configured trust anchor.
It does not authorize invocation or guarantee service trustworthiness.

## Level 1 materials

- [Presentation PDF](A3-PS033-TC378-Level1.pdf)
- [Editable presentation](A3-PS033-TC378-Level1.pptx)
- 

The presentation links assume the two files are uploaded at the repository root.
Remove the editable-presentation link if only the PDF is uploaded.

## Implementation scope

An initial local Python prototype demonstrates actual DNS queries, DNSSEC
validation, HTTPS and service-specific credentials. Diagnostic outputs are
simulated and labelled as mock. It uses a local trust anchor rather than a public
DNS root chain. The documented profile pins DNS-AID draft -02 and uses local
private-use metadata extensions. It is not a complete implementation of the draft.

The test scenarios include valid discovery, altered DNS records, signed but
malformed metadata, unavailable endpoints and incorrect service credentials.
We plan to refine deployment and evaluation during the mentoring phase.

## References

- [AIORI-3 hackathon guidelines](https://portal.aiori.in/aiori-3/hackathon-guideline/)
- [DNS-AID draft -02](https://datatracker.ietf.org/doc/html/draft-mozleywilliams-dnsop-dnsaid-02)
- [RFC 9460: SVCB](https://www.rfc-editor.org/rfc/rfc9460.html)
- [RFC 4033: DNSSEC](https://www.rfc-editor.org/rfc/rfc4033)
