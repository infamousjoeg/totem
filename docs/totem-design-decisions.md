# totem design decisions

Resolved in the grill session on 2026-09-05. Each entry is the decision and the reason it beat the alternative. Supersedes anything in totem-design.md that disagrees.

## 1. What totem promises against a same-user malicious process

Two separate claims, both on the README's first screen.

Credential theft and reuse: eliminated. Nothing durable exists on the laptop, nothing works off the device, nothing survives revocation.

Credential use in place by a co-resident process: gated by human presence. Every exchange requires the tool's SVID and a fresh presence assertion, a signature over an issuer challenge from a biometric-gated key (Secure Enclave with Touch ID, TPM with PIN, passkey or security key on Linux, terminal confirmation as the floor). The two are bound WIMSE-style so neither is useful alone. Malware that runs the real `aws` binary hits a fingerprint prompt it can't answer, which is both a block and an alarm. The issued credential carries device, tool, and "human authorized at T" so downstream policy can require it.

Rejected: "bounded, not prevented" wording. Presence is the same primitive Conceal already relies on, so it's consistent and it turns the claim from a caveat into a feature.

## 2. Tool identity anchor

Pin-on-init is the default everywhere. `totem init` records each tool's hash. On change the agent refuses the tool until `totem trust <tool>` is run and shows old and new hash.

Vendor Team ID verification is automatic hardening when the binary carries a pinned vendor signature. New versions from vendor installers need no re-trust. `totem status` shows which anchor each tool has.

Script-wrapped tools get no identity. npm Claude Code and pip or brew Python `aws` run as an interpreter; attesting the script is attesting a file any same-user process can rewrite. `init` detects it, explains it, and points at the native installer. No exceptions.

Rejected: Team ID as the default. Homebrew installs are ad-hoc signed and most people use Homebrew.

## 3. Attaching to an existing SPIRE deployment

totem never speaks SPIRE's agent-to-server protocol. The totem issuer is a device CA. In SPIRE mode the device certificate from enrollment is the credential for SPIRE's built-in `x509pop` node attestor; the platform team adds totem's device CA to SPIRE server config. A real `spire-agent` runs on the laptop and serves the Workload API. totem's bridges, presence gating, and `init` wiring run over the SPIRE agent's socket. The parent walk moves into the bridge helper in this mode. `totem export-entries` prints SPIRE registration entries for the device.

Rejected: reimplementing SPIRE node attestation. Large, private, version-sensitive surface.

## 4. Who the Claude bridge is for

Two variants, both v1, Claude stays first.

API and Bedrock users: proxy variant. Org key lives on the broker, laptop gets a five-minute opaque bearer, presence-gated. Ships first inside step 3 because it's what a security team evaluates.

Pro and Max users: injection variant. `totem run claude` exchanges SVID plus presence for the OAuth token and injects CLAUDE_CODE_OAUTH_TOKEN into the child process only. Broker holds the setup-token via Summon. A long-lived token still exists, on the broker rather than the laptop. Check Anthropic's terms on subscription token use before advertising it.

README's first paragraph says which one you are. Bedrock documented as preferred for anyone on AWS, since it makes the Claude bridge the AWS bridge.

Rejected: AWS first. More universal, nobody screenshots it.

## 5. Admin authentication for enrollment approval

One method: passkeys. First passkey registered during `totem issuer init` on the box before any listener is up.

Browser path: approval URL, passkey signs the challenge, screen shows device fingerprint, hostname, OS, and key protection level, admin types the code.

Headless path: `totem approve <code>` from any already-enrolled device signs the same challenge with that device's presence-gated key. First laptop is approved on the console at bootstrap; every later device from an enrolled one. SSH is never in the loop after day zero.

SSH certificate bridge (SVID to short-lived SSH cert) is a v1.x bridge.

Rejected: approve over SSH. Makes the operator's SSH key the long-lived secret that controls enrollment.

## 6. Claude proxy enforcement

Per-device rate limit and per-device daily spend cap, default-on with conservative values, in the same policy file as everything else. Upstream host allowlist hardcoded to Anthropic API hosts. Bearers are opaque random tokens looked up server-side, never signed JWTs. Metadata-only logging as a property of the code; request bodies never reach a logger. No model allowlist; that belongs in SWA or the org's console.

## 7. First-contact trust in the issuer

Enrollment pins the issuer. `totem issuer init` generates a self-signed server cert and prints its fingerprint. `totem enroll` fetches it, prints the fingerprint, and requires the human to confirm the match. Pinned in the enrollment record; later connections require that leaf or a successor signed by the issuer's server CA. Publicly trusted certs are still pinned. Works on a Tailscale or LAN address with no DNS.

## 8. Presence windows

Shipped in the local policy file, visible and editable.

`claude`: presence at session start, one-hour window; covers the bearer refresh and anything `aws` or `gh` do inside Claude Code's bash tool. `aws`: fifteen minutes per named profile; a profile can be `presence: always`. `gh` and `git`: fifteen minutes, one shared window.

Unattended mode is per device, per tool, opt-in via `totem allow-unattended <tool>`, logged on the issuer, shown in `totem status`. No global switch.

The window is evaluated on the issuer, not the laptop. The agent forwards the assertion with its timestamp; the issuer decides freshness. A compromised agent can't extend its own window.

## 9. Issuer state, backup, rotation, compatibility

State is one SQLite file (enrollments, policy, revocations, issuance log) plus CA material. `totem issuer backup` and `restore`, tarball encrypted under a Summon-resolved passphrase.

Root CA generated at `issuer init`, held offline or in KMS. Intermediate signs everything, rotates every 30 days with overlap; bundle endpoint publishes current plus next. Relying parties trust the root. Root rotation is a deliberate operator action with documented overlap.

Restore from an older backup is survivable: devices enrolled after the backup fail cleanly and re-enroll.

Compatibility: agent N works with issuer N and N+1; issuer refuses agents older than N-1 with a clear message. Forward-only schema migrations on start.

## 10. Summon provider hardening and secret rotation

On start and every resolve: config file, provider binary, and every directory in its path must be root-owned and not group or world writable. Failure is fatal and names the path. Provider hash recorded at `issuer init`, logged on every resolve, re-pinned via `totem issuer trust-provider`.

Provider exec'd with a clean environment, fixed PATH, timeout. Reference names validated against a strict pattern before becoming argv.

Rotation is pull-based: re-resolve every reference on an interval (default one hour) and on SIGHUP. Atomic replacement, in-flight requests finish on the old value, no restart. Values in mlocked memory, core dumps disabled, zeroed on replacement.

## 11. Trust domain, algorithms, JWT details

Trust domain defaults to the issuer hostname given at `enroll`, validated as a legal SPIFFE trust domain. IP-only issuers require an explicit trust domain at `issuer init`. Never `example.org`, never `local`.

ECDSA P-256 for device keys and SVIDs, P-384 for the CA. No Ed25519. FIPS Go crypto module; in FIPS mode the issuer refuses non-approved configuration.

JWT-SVIDs for Octo STS: issuer is the discovery provider URL, audience is the Octo STS URL, both on the compose network. Five-minute lifetime. Presence and protection-level ride as custom claims so Octo STS trust policies can match on them.

## 12. Scope split

v1: standalone issuer, macOS and Linux agent, presence gating, Claude proxy variant, Claude subscription variant, AWS Roles Anywhere, GitHub via Octo STS, Summon-protocol secrets, backup and restore, `doctor`, `status`, `revoke`. Bedrock documented as preferred Claude deployment on AWS.

v1.x, each its own release: SPIRE mode via x509pop. SSH certificate bridge. Windows agent with TPM. Linux `totem run` escape hatch via summon file or keyring provider with the loud warning. Generic OIDC exchange configurable without code.

Never: fleet management, policy planes, org audit, hosted issuer, dev mode, interpreter-wrapped tool attestation, model allowlists in the proxy.

SPIRE mode is v1.x because it's the credibility feature for platform teams, not on the solo dev's first hour, and shipping it complete matters more than shipping it early.

## 13. Repo, license, distribution

`github.com/infamousjoeg/totem`, single Go module, `cmd/totem` (agent) and `cmd/totem-issuer` (broker). Shared code for the Summon protocol, SPIFFE types, and presence assertion format; separate binaries so the issuer never ships Secure Enclave code and the agent never ships the CA.

Apache 2.0. DCO sign-off, no CLA.

Agent via the existing `infamousjoeg/homebrew-tap`. Issuer as a container image. GitHub Releases for both with Sigstore signatures and SLSA provenance. macOS agent notarized from the first release under the existing Apple Developer account (Infamous Endeavors LLC); that Team ID is a signing identity, not project branding, and is what totem pins for its own self-check.

Name check before first commit: `totem` repo name under infamousjoeg, brew formula name in the tap, `totem.dev` or `totem.sh` for docs with GitHub Pages as the fallback.

## 14. Presence state lives on the issuer

The assertion is a one-shot signature over an issuer challenge bound to device, tool, and (for `presence: always`) the request. The issuer records the session; the laptop holds nothing replayable. Rejected: agent-side cached assertions, which are bearer tokens in memory for the length of the window.

## 15. Presence gates whichever step the issuer controls

For AWS the exchange happens at Amazon, so the presence-gated artifact is a per-profile aws SVID with a fifteen-minute lifetime, minted only after presence. General rule for any bridge where the relying party is called directly.

## 16. No terminal confirmation

A daemon has no TTY and a malicious caller owns its own. Presence types are biometric-gated key, TPM PIN, passkey or FIDO touch, or approval from another enrolled device. Hardware with none enrolls as `presence: none`, recorded and carried, and still works. Honest beats fake.

## 17. Root admin is the first enrolled device

WebAuthn requires a registrable domain, and a headless VPS can't register a passkey on its console. `issuer init` prints a one-time bootstrap code; the operator's enroll with it is auto-approved as the founding device. Passkeys are optional, browser-path only, require a hostname (Tailscale MagicDNS documented as the default), and are registered from an enrolled device. `totem issuer recover` on the box is the recovery path.

## 18. Fingerprint in the enroll URL fragment

`issuer init` prints the complete enroll command with `#sha256:...`; the agent verifies and refuses on mismatch. Humans never compare hex. Bare URL falls back to a prompt with a warning.

## 19. Injection variant delivery is decided by verification

If Claude Code scrubs `CLAUDE_CODE_OAUTH_TOKEN` from child environments, env injection is acceptable. If not, env is off the table (every bash-tool command and MCP server would inherit it) and the token goes into the Keychain entry Claude Code reads with an ACL scoped to the claude binary; Linux uses the credentials file, 0600, removed on exit. Token is per human; totem-side revocation is the per-device control.

## 20. GitHub: user access tokens for developers, Octo STS for automation

Installation tokens attribute pushes and PRs to the App's bot, which breaks branch protection expectations and is a nonstarter for daily work. GitHub App user access tokens act as the developer and expire in eight hours; one-time device flow per user, broker holds the refresh token via Summon. Octo STS stays for automation-style use. Both behind one `git-credential-totem`, installed on PATH and configured as `helper = totem` so git execs it directly.

## 21. cgo on macOS only

Secure Enclave and LocalAuthentication are only reachable through Apple frameworks. cgo for the macOS platform layer, static pure Go everywhere else. TPM on Linux is pure Go.

## 22. Team ID plus signing identifier

Vendors sign many binaries. Catalog entries are `{name, team_id, signing_id, expected_paths}`. Signed downgrades accepted in v1; minimum-version is v1.x.

## 23. Proxy usage counting and rejection UX

Spend cap counts usage from streamed `message_delta` events, enforced at request start against the running total, approximate to one request. Rejections return a body naming the cap and reset time.

## 24. Roles Anywhere details

Helper presents leaf plus current intermediate. Issuer publishes a CRL to the trust anchor for immediate revocation. Certificate profile and SAN URI condition key verified before step 4.

## 25. Two kinds of secret on the issuer

Operator-provided secrets are references resolved through Summon, read-only. Issuer-managed secrets that it generates or that rotate on use (GitHub refresh tokens) live in SQLite envelope-encrypted under a data key resolved through Summon. Summon providers can't write, so this split is forced.

## 26. The issuer has its own identity

`spiffe://<td>/issuer`, no presence, one purpose: publishing CRLs to Roles Anywhere through its own profile and a role limited to ImportCrl and UpdateCrl. Which CA must sign the CRL is verified before step 4.

## 27. Single-human issuer in v1

One human, N devices. No user model. Multi-human is SPIRE mode plus a workload access product, or a later release.

## 28. One OS-signed shell hop in the parent walk

Allowed only when the shell is a system shell from a non-user-writable path and the grandparent is the attested tool. Verified per tool; apiKeyHelper spawn behavior is a step-3 verification task.

## 29. Subscription variant is conditional

Ships only if env injection is scrubbed from children or Keychain injection is honored. Otherwise it waits for a hook and the README says so. `init --claude` is explicit and refuses conflicting configuration.

## 30. Explicit admin flag

Founding device is admin. Approval, grant-admin, and revoke-admin require an admin device. Last admin can't be revoked; `issuer recover` on the box is the fallback. Bootstrap code never reaches structured logs.

## 31. Broker runs the GitHub device flow

Device flow needs only the client ID. The issuer shows the user code through the agent, polls GitHub, and receives tokens directly. The laptop never touches the refresh token.

## 32. Admin operations are always presence-gated

Approve, grant-admin, revoke-admin, and revoke ignore windows. A `presence: none` admin can approve, and the approved enrollment records it. Data key rotation via `issuer rotate-data-key`; issuer self-issuance is its own logged event type.

## 33. Experience rules (UX pass 1)

README leads with the outcome; `init` detects the Claude variant. Issuer `init` is a wizard with flag equivalents; bridges prompt for their own secrets; quickstart is fifteen minutes measured. Refusals and pending prompts fire native notifications and land in `totem log`; presence prompts time out at sixty seconds. `init` keeps a change manifest so `uninstall` is exact. Everyday verbs top-level, device admin under `totem devices`. No SPIFFE vocabulary in user-facing output. "Losing a device" page and backup scheduling exist before v1.

## 34. From the first engineer response

Unattended execution is a distinct identity with `presence: none` in the credential, never a longer window; relying-party policy scopes it. MCP server secrets (PAT in an env block) are a first-class GitHub bridge use case via `totem run --`, not an escape hatch. Fail-closed and concentration are stated on the README's first screen with the mitigations: issuer placed where relying parties are reachable, credential lifetimes ride out outages, Roles Anywhere needs no issuer secret, GitHub App key in KMS or PKCS#11, Bedrock removes the Anthropic key; goal is no extractable bearer secret on the issuer with the API key as the one stated exception. Issuer restore from backup in under ten minutes is a measured release gate.

## 35. Agents are delegated identities

Three presence states in every credential: present, delegated, none. Long-running agents run under their own OS user, get their own identity via the existing uid attestation, and operate inside a presence-signed grant (scope, expiry, spend cap) that lives on the issuer. Out-of-grant requests park and step up to the human's enrolled devices. Grants renew with presence, lapse cleanly, revoke instantly. Rejected: a longer window for unattended use. `allow-unattended` becomes the degenerate case under the human's own uid, producing `presence: none`.

## 36. From the second and third engineer responses

The ride-along sentence is a load-bearing claim and stays on the README's first screen. The translation-layer thesis (totem never asks anything to accept an SVID) leads "Why this exists." Policy is signed by admin devices; the issuer refuses unsigned policy and chains the signed records with issuance. Three presence levels per target: window, always, step-up, plus second-request warnings and a prompt-rate ceiling. Threat model gains a third claim: in-scope abuse is detectable and revocable, not prevented; the spend cap is Claude-only. Hostile-operator scope moves with the mode; SPIRE mode states the inherited trust. Shadow grants and `agents propose` are v1. Helpers emit typed exit codes and structured JSON errors with backoff hints. TPM enrollment attests hardware residency in v1; Secure Enclave is TOFU and labeled unattested until App Attest is evaluated.

## 37. From Cassidy (delegated agent, first review from inside the model)

Parking is async and resumable (`parked, id=X`, polled across heartbeats), never blocking. Parked items split by reversibility: reversible queues for one-tap morning approval, irreversible waits for presence with no pre-signing; pre-blessed lists enumerate operations, never categories. Money is a grant primitive with per-transaction and per-day ceilings and a presence floor. Grants scope by entity and action within a relying party. The README states that totem governs credentialed relying parties and outward communication is the harness's job. `~/.totem/last-error` JSON is the machine error contract; exit codes are the fast path. `agents propose` outputs three layers with the ceiling shown as prominently as the grant. Self-narrowing is instant and monotonic, inherits expiry and lineage, can never drop logging or the kill switch, and re-widening requires presence. Provenance framing: agents should want to be legible.

## 38. The rollback witness is the fleet

Raised during the step 2 review, which asked where the chain head witness lives and correctly refused to answer it from inside the store package.

The chain is tamper-evident forward and not against rollback. Truncating the tail and rewriting the recorded tip leaves a prefix with no broken link and no gap in the ordinals, and cutting back past a revocation restores access a human took away.

A witness the issuer host keeps for itself does not close this. That host holds the signing key, so it can produce any head it likes and sign it. The asymmetry available to us is that a value already delivered to a device cannot be recalled. So agents hold the highest `(seq, hash)` the issuer has shown them and require proof on each contact that the record is still in the chain being served. It ships with the versioned agent protocol: a protocol field, agent-side persistent state, and a consistency endpoint.

Restore is a separate and cheaper case, closed now. A restore that moves the chain backwards, or onto a chain that is not the live one's own history, is refused; the live head is re-read under the lock so an append during decryption cannot slip past. Deliberate rollback restores into a fresh directory.

Interim, not a substitute: the issuer states its head at open and after every restore, and the log stream already leaves the box. An attacker holding the host also holds the emitter, so this catches operator error and a clumsy rollback, nothing stronger, and it is commented that way.

## Carried from adversarial QA without a separate decision

- Threat model out of scope: compromised kernel or root, physical attacks on the secure element, hostile issuer operator.
- `totem doctor` verifies the three config surfaces (`~/.claude/settings.json`, `~/.aws/config`, git credential config) still match what `init` wrote, checks clock skew against the issuer, and reports tool anchors.
- Enrollment approval shows device fingerprint, hostname, OS, and protection level; codes are typed, not clicked; browser-path codes are bound to the requesting IP.
- Workload API conformance against go-spiffe and spiffe-helper in CI from step 1.
- Issuance log is hash-chained; structured logs to stdout with optional syslog or OTLP export; retention is the operator's problem.
- Revocation model stated plainly: short TTL plus live enrollment check at every exchange; worst-case window is one SVID TTL for local use, zero for exchanges.
- Claude Code sandbox allowance for the totem socket tested and documented early in step 3.
- Multiple AWS profiles supported at `init`, each with its own Roles Anywhere profile and role ARN, sharing the aws identity.
- Verify the native Claude Code binary carries an Anthropic Team ID and record its signing identifier before step 1.
- Presence sessions are never persisted; an issuer restart means every tool prompts once.
- Bootstrap and recovery codes are single-use, short-lived, printed once, and logged as events.
- `presence: always` defaults on for aws profiles whose role name contains `admin` or `prod`.
- Presence prompts name the tool, target, and device; `presence: always` prompts show a request code the CLI printed.
- `totem revoke` exists from v1; `enroll` offers a device name so inventory stays true across reinstalls.
