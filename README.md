# totem

SPIFFE for the machine in front of you.

Run one binary on your laptop and `claude`, `aws`, and `gh` stop needing secrets. Your device proves who it is with a key that never leaves hardware. Each tool gets its own SPIFFE identity. A small box you own turns those identities into short-lived credentials at the moment they're needed, and only when a human is present. Nothing static ever lands on the endpoint.

Named for the object in Inception that only you know the weight of, and that you never let anyone else touch.

**Credential theft and reuse: eliminated.** There is nothing durable on the laptop to steal. Identities are bound to a hardware key that can't be exported. Credentials are minted per request, expire in minutes, and are tied to one device and one tool. Revoke the device and everything stops on the next request.

**Credential use in place by a co-resident process: gated by human presence.** The rogue process hits a fingerprint prompt it can't answer, which is both a block and an alarm. Within a window, everything that tool does is authorized, including by an attacker; that's what `presence: always` targets are for.

**Not yet functional.** This repository is a scaffold: package layout, types, and doc comments only. No CA, no socket, no attestation code. The design lives in `docs/totem-design.md` and `docs/totem-design-decisions.md`.

Apache 2.0. Contributions take a DCO sign-off; see CONTRIBUTING.md.
