# totem

[![ci](https://github.com/infamousjoeg/totem/actions/workflows/ci.yml/badge.svg)](https://github.com/infamousjoeg/totem/actions/workflows/ci.yml)
[![go](https://img.shields.io/github/go-mod/go-version/infamousjoeg/totem)](go.mod)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![status](https://img.shields.io/badge/status-pre--release-orange)](#where-this-actually-is)

SPIFFE for the machine in front of you.

Run one binary on your laptop and `claude`, `aws`, and `gh` stop needing secrets. Your device proves who it is with a key that never leaves hardware. Each tool gets its own SPIFFE identity. A small box you own turns those identities into short-lived credentials at the moment they're needed, and only when a human is present. Nothing static ever lands on the endpoint.

Named for the object in Inception that only you know the weight of, and that you never let anyone else touch.

**Credential theft and reuse: eliminated.** There is nothing durable on the laptop to steal. Identities are bound to a hardware key that can't be exported. Credentials are minted per request, expire in minutes, and are tied to one device and one tool. Revoke the device and everything stops on the next request.

**Credential use in place by a co-resident process: gated by human presence.** The rogue process hits a fingerprint prompt it can't answer, which is both a block and an alarm. Within a window, everything that tool does is authorized, including by an attacker; that's what `presence: always` targets are for.

## Where this actually is

Not usable yet, and specific about why. This section is kept current as
things land rather than written at the end, so it is worth trusting.

**The agent works.** A real, unmodified `go-spiffe` client fetches an X509-SVID
from totem's socket and verifies it chains to the issuer bundle, and rotation is
pushed to a held stream rather than polled. The device key lives in the Secure
Enclave with the presence gate in the key's own access control, not in totem's
control flow: loading the presence key under a non-interactive context and asking
it to sign is refused by the SEP itself. Tool identity is decided by asking the
kernel what code is running in a process and cross-checking it against the
signature on disk, which closes replacing the file after it has started.

**The issuer works.** A founding device enrolls with a bootstrap code and gets an
SVID, through a real CA, a real SQLite store and a real policy engine. Admin
operations are signed records in the same tamper-evident chain as issuance. The
intermediate rotates every thirty days with three live at once, so no unexpired
credential breaks at a handover.

**What is not here.** None of the three bridges: `claude`, `aws` and `gh` do not
yet get credentials through totem. There is no deployment story, no released
binary, and nothing has run anywhere but a development machine.

**What is deliberately incomplete.** Linux TPM attestation compiles and is
vetted but has never run against real silicon. Certificate extensions carry a
placeholder OID arc; a release build refuses to link until a real IANA
enterprise number replaces it. Revocation is not checked against OCSP or a CRL,
and a code signature's timestamp is not verified, both of which are documented
where they matter rather than implied away.

The design lives in `docs/totem-design.md` and `docs/totem-design-decisions.md`.

Apache 2.0. Contributions take a DCO sign-off; see CONTRIBUTING.md.
