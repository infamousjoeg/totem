# totem

[![ci](https://github.com/infamousjoeg/totem/actions/workflows/ci.yml/badge.svg)](https://github.com/infamousjoeg/totem/actions/workflows/ci.yml)
[![go](https://img.shields.io/github/go-mod/go-version/infamousjoeg/totem)](go.mod)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![status](https://img.shields.io/badge/status-pre--release-orange)](#status)

SPIFFE for the machine in front of you.

Run one binary on your laptop and `claude`, `aws`, and `gh` stop needing secrets. Your device proves who it is with a key that never leaves hardware. Each tool gets its own SPIFFE identity. A small box you own turns those identities into short-lived credentials at the moment they're needed, and only when a human is present. Nothing static ever lands on the endpoint.

Named for the object in Inception that only you know the weight of, and that you never let anyone else touch.

**Credential theft and reuse: eliminated.** There is nothing durable on the laptop to steal. Identities are bound to a hardware key that can't be exported. Credentials are minted per request, expire in minutes, and are tied to one device and one tool. Revoke the device and everything stops on the next request.

**Credential use in place by a co-resident process: gated by human presence.** The rogue process hits a fingerprint prompt it can't answer, which is both a block and an alarm. Within a window, everything that tool does is authorized, including by an attacker; that's what `presence: always` targets are for.

## Status

You cannot use this yet. No bridges, no release, no deployment. `claude`,
`aws` and `gh` still use their own credentials.

The agent serves the SPIFFE Workload API on a unix socket, and an unmodified
`go-spiffe` client fetches an SVID from it and verifies the chain. Rotation is
pushed down the stream. On Apple silicon the device key lives in the Secure
Enclave and the presence gate is the key's own access control, so a signature
without a human is refused by the SEP rather than by our code. Tool identity
comes from asking the kernel what is running in a process and comparing it to
the signature on disk, so swapping the file after exec does not work.

The issuer enrolls a founding device from a bootstrap code and issues it an
SVID. Admin actions are signed records in the same hash chain as issuance.
The intermediate rotates every thirty days with three live at once, so
credentials issued under the outgoing one keep working.

Known gaps, all deliberate. Linux TPM attestation compiles but has never run
on real hardware. The certificate extensions use a placeholder OID arc and a
release build will not link until a real IANA number replaces it. Revocation
is not checked, and code signature timestamps are not verified.

Design: `docs/totem-design.md` and `docs/totem-design-decisions.md`.

The [wiki](https://github.com/infamousjoeg/totem/wiki) covers the decisions that took real work, at the length the reasoning needs: why the Secure Enclave holds two keys, why tool identity comes from the kernel rather than from the file, and why a release build refuses to link today.

Apache 2.0. Contributions take a DCO sign-off; see CONTRIBUTING.md.
