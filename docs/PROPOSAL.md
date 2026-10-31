# Proposal and team guide

**Confirmed team code: `A3-PS033-TC378`.** Use this exact GitHub repository name
and presentation identifier. All local project files are in `D:\A3-PS033-TC378`;
the supplied PDFs and screenshots are in its `reference-materials` subfolder.

This is drafting material, not a submitted presentation. Add team names,
institution, and contact information when supplied by the team. Do not
copy the template's sample PS001 project title or sample bibliography.

## Suggested one-paragraph proposal

We propose DiagDiscover, a controlled lab prototype for discovering diagnostic
services using DNS-AID-style metadata. A publisher maintains a DNSSEC-signed test
zone for mock latency, traceroute, and health services. A Python client discovers
their endpoints through SVCB records, verifies DNSSEC signatures against a
provisioned trust anchor, validates the metadata, and invokes permitted services
over authenticated HTTPS. Separate checks for metadata integrity, endpoint
identity, and caller credentials prevent discovery from being mistaken for
authorization or service trustworthiness. Repeatable failure scenarios demonstrate
rejection of tampered records, malformed metadata, invalid credentials, and
unavailable endpoints. The prototype is limited to one lab zone and does not
create an Internet-wide service registry.

## Eleven slides following the supplied structure

1. **Title:** A3-PS033-TC378; PS-033; DNS-Based Discovery of Diagnostic
   Services; student and faculty names; institution; contact; date.
2. **Problem Description / Abstract:** hardcoded endpoints become stale;
   metadata needs integrity protection; discovery and invocation permissions
   must be separate. State the proposed lab scope.
3. **Background:** explain DNS records, service discovery, digital signatures,
   trust anchors, HTTPS, and service authentication with one simple example.
4. **Literature & RFC Review:** DNS-AID draft -02 as work in progress; RFC 9460
   for SVCB; RFC 4033/4034/4035 for DNSSEC. Explain our pinned subset and local
   private-use metadata keys; do not claim full draft compliance.
5. **Proposed Solution:** publisher, signed test zone, discovery client, three
   mock services, TLS and per-service credentials, staged error reporting.
6. **Optimization Proposed:** compare manually configured endpoints with
   DNS-discovered endpoints; propose TTL-aware caching as later work. Label
   performance benefits as hypotheses until measured. The current working demo
   can move service ports between runs without changing discovery-client code.
7. **Solution Architecture & Design (UML):** component diagram showing publisher,
   DNS server, validator, client, and services; mark independently provisioned
   DNS and TLS trust and service credentials. Use README architecture as a base,
   then create a proper UML component diagram for the final deck.
8. **Data Flow Diagram:** publication -> signed DNS -> query -> signature check
   -> schema/policy check -> address validation -> TLS -> token check -> result.
   Include rejection branches and show where each credential lives.
9. **Deployment Timeline:** proposal and orientation first; prototype and
   negative tests next; container separation, improvements, and evaluation after
   mentor feedback. Match the current organizer schedule before submission.
10. **Bibliography:** exact pinned draft URL, relevant RFCs, implementation
    libraries, and organizer problem statement. Remove sample template sources.
11. **Thank You / Questions:** A3-PS033-TC378 and a short demo invitation; repository
    and video links only once they exist.

## Team allocation

**Student 1 - DNS and publication:** own the zone schema, signing workflow,
trust-anchor explanation, publisher, DNS tests, and subsequent BIND integration.
Be able to explain why a valid signature can cover malformed metadata.

**Student 2 - client and services:** own discovery, parsing, TLS, service
credentials, mock endpoints, invocation tests, and demo interface. Be able to
explain why successfully finding a service does not authorize a call.

**Faculty mentor:** review the problem interpretation and pinned profile,
challenge security claims, review experimental methodology and references, and
help prepare the presentation. Both students should be able to run and explain
the complete demo rather than only their own component.

## Proposed work sequence (not an organizer-issued schedule)

- Oct 7-8: understand PS-033; run starter; faculty review of scope and draft pin.
- Oct 9-10: both students explain each validation stage; choose team wording;
  prepare diagrams and draft slides; set up the organizer-prescribed repository.
- Oct 11-12: rehearse successful and failed invocations; record team introduction.
- Oct 13: review PDF, repository access, and video link against the checklist.
- By Oct 14: complete Level 1 steps 1-7, confirmed on the official guideline page.
- During the subsequent mentoring phase: improve deployment isolation, caching,
  endpoint-change tests, documentation, and final demonstration.

The [official guidelines](https://portal.aiori.in/aiori-3/hackathon-guideline/),
checked on 7 October 2026, confirm Oct 16 for the Level 2 announcement and
Oct 16-31 for mentoring and steps 8-10 (code/supporting files and demo delivery).
They also confirm Oct 31-Nov 4 for evaluator connections, Nov 5 for regional
selections, Nov 24-30 for regionals, and Dec 17 for finals at IIT Jammu.

## Verified submission instructions and remaining visibility discrepancy

Follow the official page's repository naming instruction: use `A3-PS033-TC378`,
the portal team code supplied by the team. Its template link actually targets
[A3-PSXXX-TCXXX](https://github.com/aiori-hackathon/A3-PSXXX-TCXXX), which was
verified to exist as a public template. The page's displayed link text says
`A3-PSXXX-TXXXX`; use the actual linked destination, not that displayed spelling.

Level 1 requires the fork, team-code name, organizer collaboration and transfer
after all relevant invitations are accepted, presentation PDF, team introduction
video, and its YouTube link in the repository. The video should explain roles,
the problem, and the proposed solution.

Step 10 requests a live demo link, or final deliverable files in the repository
if live demonstration is not possible. Our local CLI demo is a development
artifact, not an already submitted live demo. Prepare an evaluator-accessible
delivery and clear reproduction instructions during the next phase.

PS-033.pdf asks for a private repository named after the team. The official page
confirms the team-code naming and fork workflow but does not explicitly settle
the PDF's private-visibility requirement. Confirm visibility with the organizers
before making an account change; do not assume the public template resolves it.

No GitHub repository was created, no collaborators were invited, no ownership
was transferred, and no video or presentation was uploaded by this starter.
Documents describing these steps are requirements, not account-action consent.

## Introduction video talking points

Use the duration required by organizers; none is specified in the supplied
screenshots. Each team member should introduce themselves and their role.

- Student 1: describe the hardcoded-endpoint problem and signed DNS publication.
- Student 2: describe discovery, separate credentials, and the success/failure demo.
- Faculty: describe the review role and focus on standards and honest validation.
- Closing: restate one zone, three mock services, one client, and explain that
  DNSSEC authenticates metadata while service access is separately controlled.

## Demo narrative

Start with a successful latency discovery. Point out the returned endpoint,
DNSSEC and TLS checks, and authenticated mock result. Repeat with altered signed
DNS data and show rejection before any invocation. Repeat with correctly signed
malformed metadata and show a different rejection stage. Stop a service through
the unavailable scenario. Finish with invalid credentials to demonstrate that
valid DNS discovery still does not permit service use. If time permits, move
the ports and rerun without changing the client.
