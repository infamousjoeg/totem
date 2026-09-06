# totem

SPIFFE for the machine in front of you.

Run one binary on your laptop and `claude`, `aws`, and `gh` stop needing secrets. Your device proves who it is with a key that never leaves hardware. Each tool gets its own SPIFFE identity. A small box you own turns those identities into short-lived credentials at the moment they're needed, and only when a human is present. Nothing static ever lands on the endpoint.

Named for the object in Inception that only you know the weight of, and that you never let anyone else touch.

## The one rule

The laptop holds no durable secrets. The broker holds references. Only a Summon provider turns an operator's reference into a value; secrets the issuer itself generates or rotates live envelope-encrypted under a Summon-resolved key. Only a present human turns an identity into a credential, and presence is checked at whichever step the issuer controls.

The v1 standalone issuer serves one human and any number of their devices. Multi-human is SPIRE mode plus a workload access product, or a later release with a real user model.

## What totem promises

Two claims, kept separate on purpose.

**Credential theft and reuse: eliminated.** There is nothing durable on the laptop to steal. Identities are bound to a hardware key that can't be exported. Credentials are minted per request, expire in minutes, and are tied to one device and one tool. Revoke the device and everything stops on the next request.

**Credential use in place by a co-resident process: gated by human presence.** Malware running as you can exec the real `aws` binary, and totem can't tell the difference from the socket. So the issuer requires two things before it produces anything: the tool's SVID, and a one-shot presence assertion, a signature over an issuer challenge from a biometric-gated key on the device, bound to the device, the tool, and for sensitive targets the specific request. Presence state lives on the issuer as a short session; the laptop never holds anything replayable. The rogue process hits a fingerprint prompt it can't answer, which is both a block and an alarm. The issued credential records that a human authorized it and when. Within a window, everything that tool does is authorized, including by an attacker; that's what `presence: always` targets are for.

**In-scope abuse: detectable and revocable, not prevented.** A hijacked agent or a ride-along process operating inside a grant or window can use everything that scope allows, repeatedly, until revoked. The Claude proxy has a spend cap because tokens are countable; AWS and GitHub have scope and a hash-chained log, and the backstop is instant revocation. Don't read the spend cap as a general rate limit.

totem is not EDR and doesn't replace it. It removes the secrets EDR was guarding and makes their replacement require a person. The sentence above about windows authorizing an attacker is a load-bearing claim and stays on the README's first screen.

**Presence has three states, and the credential always says which.** `present`: a human touched the sensor. `delegated`: a human granted an agent a scope once, with presence, and the agent operates inside it until the grant expires or is revoked. `none`: a device with no presence capability, recorded as such. A longer window is never one of the options. See "Agents and delegation" below.

**Fail-closed, said plainly.** When the issuer is unreachable, tools stop; nothing degrades. Place the issuer where the relying parties are reachable from (a public VPS, not a home LAN behind a flaky tailnet) and the failure mode is the same as losing the internet. Credential lifetimes (eight-hour GitHub tokens, one-hour Claude windows) ride out short outages.

**Concentration, said plainly.** The issuer replaces N keychains with one box, so the box has to hold less than a keychain does. Roles Anywhere needs no secret on the issuer, only the CA, whose key lives in hardware or KMS. The GitHub App key is a signing key and lives in KMS or a PKCS#11 token, never in memory. With Bedrock, no Anthropic key exists. The stated goal: with Bedrock and a KMS-backed signer, the issuer holds no extractable bearer secret, and every credential it issues is device-bound, logged, and minutes long. The Anthropic API key, when used, is the one exception and the README says so.

## Why this exists

SPIFFE solved workload identity and shipped it as a datacenter platform. Teams that evaluate SPIRE mostly walk away for two reasons: nothing accepts an SVID out of the box, and day-two operations can consume a team of engineers.

totem sidesteps the first reason entirely. It never asks anything to accept an SVID. It translates a device identity into whatever each relying party already accepts: a Roles Anywhere trust anchor for AWS, a GitHub App token for gh, SigV4 for Bedrock, an OIDC token for anything federated. That translation layer is the unlock; the SPIFFE identity underneath is what makes it composable rather than a pile of one-off helpers. Neither of those teams is ever going to exist for a single developer, so a laptop deployment has to be zero day-two from the start.

totem is not a SPIRE replacement and not a fleet product. It is the on-ramp. It works standalone with its own embedded issuer, or attaches to an existing SPIRE deployment so a platform team's identity system finally has a laptop story. Fleet policy, org-wide audit, and deciding which identity may become which cloud role are the job of a workload access product such as Idira Secure Workload Access. totem stops where that starts and points at it.

## Threat model

Attackers, in priority order:

1. Malware or a rogue package postinstall running as the user. Theft: eliminated. Use in place: presence-gated.
2. A stolen or imaged laptop. Nothing durable to recover; revocation cuts it off.
3. A compromised dev tool spending its identity on something it wasn't given. Per-tool identity, per-tool scope, presence windows.
4. A compromised broker box. It holds the exchange secrets, which is unavoidable, but no device keys and no way to enroll devices without passkey approval.

Out of scope: a compromised kernel or root on the laptop, physical attacks on the secure element, and a hostile issuer operator in standalone mode, where the operator is the user. In SPIRE mode the operator is the platform team and the developer inherits their device-CA trust, their registration entries, and their revocation behavior; the social contract changes with the mode and the SPIRE mode section says so.

## Components

Two processes, always separated. Even for one person, the broker runs somewhere other than the laptop: a small VPS, a homelab box, a Fly machine, a Tailscale node. The Claude bridge only means something if the real key never touches the endpoint.

```
 laptop                                      broker box (headless)
 ┌────────────────────────────┐              ┌─────────────────────────────┐
 │ totem agent                │   mTLS       │ totem issuer                │
 │  device key (SE/TPM)       │◄────────────►│  CA (root offline, 30-day   │
 │  presence-gated signing    │  (pinned)    │      rotating intermediate) │
 │  Workload API (unix sock)  │              │  enrollment (passkey admin) │
 │  attestor: pin + Team ID   │              │  OIDC discovery (JWKS)      │
 │  bridges: claude aws gh    │              │  exchanges: claude aws gh   │
 └──────┬─────┬─────┬─────────┘              │  presence window policy     │
        │     │     │                        │  secrets via Summon provider│
     claude  aws   git/gh                    └──────────────┬──────────────┘
                                                            │
                                          Anthropic API / Roles Anywhere / Octo STS
```

### Agent (laptop)

- Device key in Secure Enclave on Apple silicon, TPM 2.0 on Linux. Keyring or 0600 file-backed software key when no hardware exists; never refused, always recorded. The protection level is carried on the identity so downstream policy can act on it.
- Hardware residency is proven where it can be. TPM enrollment includes standard attestation (EK certificate to the vendor root, attestation key certified by the EK, device key certified by the AK), verified by the issuer in pure Go. Apple silicon has no general key attestation for third-party apps outside App Attest, which needs an entitlement; until that's evaluated, Secure Enclave enrollment is trust-on-first-use and recorded as `secure-enclave, unattested`. The "cannot be exported" claim is proven from t=0 on TPM and stated on Mac.
- Presence: the device key, or a companion key, is created with a user-presence access control. Signing an issuer challenge requires Touch ID, TPM PIN, a passkey or FIDO security key touch, or approval from another enrolled device. There is no terminal confirmation floor, because a malicious caller owns its own TTY. Hardware with none of these enrolls with `presence: none`, recorded and carried on the identity, and exchanges still work. The prompt always names the tool, target, and device, and for `presence: always` targets shows a short request code the CLI printed.
- Standard SPIFFE Workload API on a unix socket, mode 0600. Anything that already speaks SPIFFE works unchanged.
- Attestation: peer credentials give the pid; start time is checked to close PID reuse. The binary is matched against the hash pinned at `init`. If the binary carries the pinned vendor Team ID and signing identifier, new versions are accepted without re-trust. When a bridge helper is the caller, the agent walks to the parent and attests that. Where a tool insists on spawning helpers through a shell, exactly one hop is allowed, only when the shell is an OS-signed system shell from a non-user-writable path, and the grandparent must be the attested tool. The git helper is installed as `git-credential-totem` on PATH and configured as `helper = totem` so git execs it directly and the parent is `git`, not `sh`.
- Interpreter-wrapped tools get no identity. `init` detects them and points at the native installer.
- SVIDs in memory only. On disk: the enrollment record and the pinned issuer certificate. Presence sessions live on the issuer and are never written anywhere.
- One-hour SVID TTL for the device identity, renewal at half-life, re-attests against the enrolled key. Bridge SVIDs that are used directly against a relying party (AWS) are minted per request after presence with a fifteen-minute lifetime; the SVID is the presence-gated artifact. No offline grace window; an unreachable issuer is a clear error and nothing else.
- `init` writes the aws profiles, the git credential helper, and the Claude Code settings, all pointing back at the agent, and warns about static keys it finds nearby. `doctor` verifies those surfaces still match, checks clock skew, and reports each tool's anchor. `status` shows enrollment, protection level, anchors, presence windows, and any unattended allowances. `revoke` exists from v1.
- Refuses the anti-patterns: never reads `.env`, never accepts a key on the command line.

### Issuer (broker box)

- One container, one config file, mTLS only. Self-signed server cert generated at `issuer init`; the printed enroll command embeds its fingerprint as a URL fragment so the agent verifies it with no human comparison. Publicly trusted certs are still pinned. A hostname is required for the browser admin path (WebAuthn cannot use an IP); Tailscale MagicDNS is the documented default. IP-only issuers get the headless path only.
- Root CA generated at `issuer init`, held offline or in KMS. Intermediate signs everything and rotates every 30 days with overlap; the bundle endpoint publishes current plus next. Root rotation is a deliberate operator action.
- The root admin is the first enrolled device. `issuer init` prints a one-time bootstrap code (to the terminal if stdout is a TTY, otherwise to a 0600 file, never to structured logs; ten-minute expiry, redemption logged with the device fingerprint). The operator's own `totem enroll` with that code is auto-approved as the founding device and flagged admin. Only admin devices can approve enrollments; approve, `grant-admin`, `revoke-admin`, and `revoke` are `presence: always` regardless of the device's windows, an approval by a `presence: none` admin is recorded as such on the new enrollment, revoking the last admin is refused, and `totem devices` lists enrollment, protection level, admin flag, and last seen. Passkeys are an optional additional admin credential for the browser path, registered from an enrolled device. `totem issuer recover` on the box prints a new bootstrap code and logs loudly.
- Runs the SPIRE OIDC discovery provider so JWT-SVIDs federate to anything that speaks OIDC.
- Exchanges are separate handlers behind the same mTLS door. Each validates the SVID, checks the enrollment is live, checks the presence assertion is fresh for the requested tool, and returns the narrowest credential that works.
- Presence windows are issuer-side sessions, evaluated here, never persisted; a restart means every tool prompts once.
- Policy is signed by admin devices, not by the issuer. Every change to enrollments, presence policy, grants, admin flags, and step-up approvals is a record signed with an admin device's presence-gated key; the issuer refuses to apply anything unsigned and stores the signed records in the same hash chain as issuance. The issuer host is a verifier and a cache of admin-signed state. A compromised host can mint under the CA (bounded by KMS) but cannot quietly widen a grant or enroll a device.
- Every issuance, exchange, and policy change is one structured, hash-chained log line: SPIFFE ID, device, tool anchor, presence type and age, grant ID, outcome. Stdout, with optional syslog or OTLP export.
- State is one SQLite file plus CA material. Issuer-managed rotating secrets (GitHub refresh tokens, presence session keys) are rows envelope-encrypted under a data key resolved through Summon; `issuer rotate-data-key` re-encrypts them, and losing the key loses only material that a device flow can regenerate. `backup` and `restore` produce a tarball encrypted under a Summon-resolved passphrase; restore requires the provider to be configured first and says so.
- The issuer has its own tool identity, `spiffe://<td>/issuer`, with no presence, every self-issuance logged as a distinct event type, used for the one AWS call it makes: publishing CRLs through its own Roles Anywhere profile and a role limited to `rolesanywhere:ImportCrl` and `rolesanywhere:UpdateCrl` on its own trust anchor.

## Identity model

No registration entries as a user-facing concept. The SPIFFE ID is derived:

```
spiffe://<trust-domain>/device/<device-id>/tool/<tool-name>
```

Trust domain defaults to the issuer hostname given at `enroll`; IP-only issuers require one explicitly. Tool names come from a shipped catalog of `{name, team_id, signing_id, expected_paths}`; Team ID alone is too broad because vendors sign many binaries. First verified entry: `{name: claude, team_id: Q6L2SF6YDW, signing_id: com.anthropic.claude-code, expected_paths: [~/.local/share/claude/versions/*, /opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe]}`, Developer ID with hardened runtime, native arm64 Mach-O in both the native and npm installs. The interpreter-wrapped exclusion does not apply to either. Signed downgrades are accepted in v1; a minimum-version field is v1.x hardening. Protection level and presence facts travel as X.509 extensions and JWT claims, never in the path.

## Enrollment

Headless first, browser as a courtesy.

1. `totem enroll https://issuer#sha256:...` (the command `issuer init` printed) fetches the issuer cert and verifies it against the fragment, refusing on mismatch. A bare URL falls back to a fingerprint prompt with a warning. Generates the device key. Prints a short code and an approval URL.
2. Approval, either path, shows device fingerprint, hostname, OS, and protection level, and requires typing the code. Headless: `totem approve <code>` from any already-enrolled device signs it with that device's presence-gated key. Browser: an admin passkey signs the same challenge. The founding device is auto-approved with the bootstrap code from `issuer init`.
3. The issuer records the public key, device ID, protection level, and pinned cert. The code is single-use and expires in minutes.
4. Later attestation is a signed challenge. Silent.

## Agents and delegation

A long-running agent woken by launchd heartbeats is not a human's tool being used without a human. It is a workload with a human sponsor, and it gets its own identity and its own rules.

**Identity.** The agent harness runs under a dedicated OS user. The unix attestor already separates on uid, so `spiffe://<td>/device/<device>/agent/<name>` falls out of the existing attestation code, and interactive tools under the human's own uid keep their present-gated identities. No new mechanism, and it doesn't matter what the harness is built from.

**Grant.** A human creates a grant with presence: which agent, which aws profiles, which GitHub repos and scopes, whether Claude via the proxy and under what spend cap, until when. The grant is the presence-signed artifact and lives on the issuer. Thirty-day default, renewal requires presence, a notification goes out three days before expiry, and if it lapses the agent keeps running but its credentials stop. Revocation is instant.

**Credentials.** Inside the grant, the agent's helpers get credentials with no prompt. Each carries `presence: delegated`, the grant ID, and the human's signing time. The issuer enforces the grant's scope before issuing; Octo STS trust policies and Roles Anywhere conditions can match on the grant claim; the proxy's per-identity spend cap is the runaway-agent fuse.

**Step-up.** A request outside the grant is parked, not refused, and parking is asynchronous and resumable: the exchange returns `parked, id=X` immediately, never blocks, and the agent polls the id on a later heartbeat. One parked task never freezes the others. Parked items split by reversibility, which is the real axis, not the clock. Reversible or internal actions (read, compute, write to the agent's own store) queue and auto-run on morning approval, so the human wakes to "here's what I wanted to do" and one tap. Irreversible or outward actions (send, post, spend, delete) stay parked until presence, with no pre-signing and no exceptions; 3am is exactly when scope must not widen. If a pre-blessed list exists, it enumerates specific operations ("may restart the board server"), never a category. The issuer notifies the human's enrolled devices with agent, scope, and duration; approvals are logged against the grant and expire on their own.

**Money is a grant primitive, not a bridge feature.** Purchases span many relying parties and need a dimension ops grants lack: amount and velocity. A grant carries per-transaction and per-day ceilings with step-up above them, and a hard floor: outward money movement above trivial is always presence, never delegated. The Claude spend cap is the seed of this, generalized.

**Per-entity tiers inside one relying party.** Reading a freezer temperature and unlocking a front door are the same Home Assistant credential. Grants scope by entity and action within a relying party, not just by relying party.

**Where the grant model stops.** totem governs credentialed relying parties. A comms-heavy agent's highest-risk act, reaching a human as its sponsor (a message, a post, an email sent as them), is often not a credential exchange, and no grant gates it. The README says the promise ends at the API boundary and that outward communication is governed by the harness, not by totem.

**Sizing.** Grants are the agent's IAM policy, and sizing them by hand is a day-two tax. `totem agents grant --shadow` runs the agent for a period under the human's widest sanctioned scope while recording every request as if it were a denial; `totem agents propose` then produces the minimal grant that would have covered the observed behavior in three layers. Top: plain language grouped by relying party and risk. Middle: a diff against the sanctioned scope framed as a reduction, because the human is signing a shrink. Bottom: raw policy, collapsed, for the record. What the agent will not be able to do is shown as prominently as what it can; for a delegated agent the ceiling is the reassurance. Rendered wherever the human already reads, with approval on a presence device.

**Self-narrowing.** An agent may derive a narrower sub-grant for itself at any time, instantly, without presence: wrap a prompt-injection surface (web content, a third-party MCP server) in a sub-identity that holds almost nothing. Narrowing may only remove capabilities, never observability or revocability; logging and the kill switch are never in scope to narrow. A sub-grant inherits the parent's expiry and grant-id lineage so the audit chain stays whole, and the parent ceiling still binds. Narrowing is monotonic within a session: re-widening back to something dropped always requires presence, because "narrow, do the quiet thing, silently restore" is a laundering path. The rule is unconditional on purpose. An earlier draft said "if any time has passed", which against a real clock is always true and so bought nothing, while reading like a loophole an implementer might try to honor.

**Blast radius.** A hijacked agent (prompt injection, a hostile MCP server) gets exactly the grant, or the sub-grant it was wrapped in, and nothing else, can abuse it until revoked, and the human has a dated record of what was authorized and what was used.

**Provenance.** Every delegated credential answers "who authorized this" with a grant id and the sponsor's signing time. An agent stops being an ambiguous extension of its sponsor and becomes something that can be audited and therefore trusted with more. Agents should want to be legible.

`totem devices allow-unattended` from earlier is subsumed: it is the degenerate grant for a tool under the human's own uid, and it produces `presence: none`, not `delegated`, because no scope was signed.

## Presence windows

Shipped defaults in the local policy file:

- `claude`: presence at session start, one-hour window. Covers the bearer refresh and anything `aws` or `gh` do inside Claude Code's bash tool.
- Three presence levels per target, named in the policy file: `window` (ride-along risk within the window, stated), `always` (per request, assertion bound to a hash of the request), `step-up` (park and approve from another enrolled device).
- `aws`: `window` of fifteen minutes per named profile, which is also the aws SVID lifetime; `init` defaults `always` for any profile whose role name contains `admin` or `prod`.
- Prompt hygiene: a prompt arriving within seconds of an approval is shown as a distinct second request, and a target can set a maximum prompt rate so a flood is itself the alarm.
- `gh` and `git`: fifteen minutes, shared.
- Unattended tools under the human's own uid: `totem devices allow-unattended <tool>`, logged, shown in `status`, produces `presence: none`. Agents under their own uid use grants instead (see above). Never a longer window. No global switch.

## Bridge: Claude Code (first)

**Proxy variant, for API and Bedrock users.** `init` sets `apiKeyHelper` to `totem claude-key`, sets `CLAUDE_CODE_API_KEY_HELPER_TTL_MS` to the bearer lifetime, points `ANTHROPIC_BASE_URL` at the issuer's Claude proxy, and sets `ENABLE_TOOL_SEARCH=true`. Claude Code spawns the helper; the agent walks to the parent, attests `claude`, issues the SVID. The helper presents SVID plus presence to the issuer and receives an opaque five-minute bearer. The proxy validates the bearer, injects the real key, forwards. The key exists only on the broker. The proxy enforces a per-device rate limit and daily spend cap, counting usage from streamed `message_delta` events so the cap is real for Claude Code, a hardcoded Anthropic host allowlist, and logs metadata only; bodies never reach a logger. Rejections return a body that names the cap and reset time.

**Injection variant, for Pro and Max users, conditional.** `totem run claude` exchanges SVID plus presence for the OAuth token and hands it to Claude Code for the session only. Whether it ships in v1 depends on a verification task before step 3: env injection is acceptable only if Claude Code scrubs `CLAUDE_CODE_OAUTH_TOKEN` from child environments (otherwise every bash-tool command and MCP server inherits it); Keychain injection is acceptable only if Claude Code honors a setup-token written in its own Keychain format without overwriting or refreshing it. If neither is safe, the variant waits for a hook and the README says so. The broker holds the setup-token through Summon. The token is per human, not per device; totem-side revocation is the per-device control. Anthropic's terms on subscription token use are checked before this is advertised.

`init --claude proxy|subscription|none` is explicit; `init` refuses to configure one variant while the other is present, and `doctor` reports the conflict. The README's first paragraph says which variant you are. Bedrock is the preferred deployment for anyone on AWS: the Claude bridge becomes the AWS bridge and the Anthropic key never exists anywhere.

Known: the VS Code extension currently ignores `apiKeyHelper`. Claude Code's sandbox allowance for the totem socket is tested and documented early.

## Bridge: AWS (second)

Roles Anywhere, using the SPIFFE project's existing `aws-spiffe-workload-helper` logic embedded rather than reimplemented. The exchange happens at AWS, not on the issuer, so the presence-gated artifact is the SVID itself: the helper asks the issuer for a per-profile aws SVID, the issuer checks presence, and mints one with a fifteen-minute lifetime. The helper presents leaf plus current intermediate; the issuer's root is the trust anchor and the issuer publishes a CRL to it for immediate revocation, using its own issuer identity. Default session duration equals the SVID lifetime, fifteen minutes, configurable per profile. `init` writes named profiles, each with its own Roles Anywhere profile and role ARN, all with `credential_process = totem aws-creds --profile <name>`. The aws SPIFFE ID is pinned in the Roles Anywhere policy. Session name records device and presence. The certificate profile is verified against Roles Anywhere's requirements before step 4.

## Bridge: GitHub (third)

Two token types behind one `git-credential-totem`, plus the MCP case, which is the thing people most want deleted: a long-lived PAT in an MCP server's env block. Claude Code launches MCP servers by command, so the config becomes `totem run -- npx <github-mcp>` and totem injects an eight-hour user token into that process only, fetched from the issuer per launch after presence (or as the unattended identity). Same injection pattern as the Claude subscription variant, and a first-class v1 use case.

For the developer's daily git and gh: GitHub App user access tokens, which act as the developer, expire in eight hours, and keep commits and PRs attributed to the human. One-time device flow run by the broker: it shows the user code through the agent, polls GitHub, and receives the tokens directly, so the laptop never handles the refresh token even transiently. The broker stores it envelope-encrypted because it rotates on every use, and exchanges SVID plus presence for a fresh access token, cached broker-side until expiry.

For automation-style use: self-hosted Octo STS. The agent requests a five-minute JWT-SVID with audience set to the Octo STS URL; the discovery provider is the issuer, both on the compose network, with Octo STS trusting the issuer's server cert. Octo STS returns an installation token scoped by the repo's trust policy, which can match on the presence and protection-level claims. Octo STS is unsupported upstream; the exchange interface stays narrow enough to replace it with a built-in installation-token exchange if needed. The GitHub App key is a signing key; KMS or PKCS#11 where available, a Summon-resolved file as the floor.

## SPIRE mode (v1.x)

totem never speaks SPIRE's node attestation protocol. The totem issuer is a device CA; the platform team adds it to SPIRE server's built-in `x509pop` node attestor. A real `spire-agent` runs on the laptop with the device cert and serves the Workload API. totem's bridges, presence gating, and `init` wiring run over that socket. `totem export-entries` prints the registration entries for a device.

## Secrets

There is no plaintext path, no `--anthropic-key` flag, no environment variable the issuer reads directly, no dev mode. Tests use a fake provider that only compiles into the test binary.

Config holds references:

```yaml
secrets:
  provider: /usr/local/lib/summon/conceal_summon
  anthropic_api_key: totem/anthropic
  claude_oauth_token: totem/claude-oauth
  github_app_key: totem/github-app
  ca_passphrase: totem/ca-passphrase
```

The issuer speaks the Summon provider protocol natively. Every existing provider works unchanged: Conceal on a Mac, summon-aws-secrets on a VPS, summon-conjur for anyone on Secrets Manager.

Hardening: config, provider binary, and every directory in its path must be root-owned and not group or world writable, checked at start and on every resolve, fatal on failure. Provider hash pinned at `issuer init`, logged on every resolve, re-pinned with `trust-provider`. Clean environment, fixed PATH, timeout, strict reference name validation. Rotation is pull-based on an interval and on SIGHUP, atomic, no restart. Values in mlocked memory, core dumps off, zeroed on replacement.

`totem secrets set <ref>` prompts on stdin and writes into the configured provider, so quickstart and production are the same command.

The file provider refuses world or group readable files, refuses paths inside a git worktree or synced folder, and logs "move these" on every start. Not silenceable.

On the laptop, `totem run <cmd>` wraps `summon -p conceal_summon` for tools without a bridge yet. Linux escape hatch via the file or keyring provider is v1.x.

## Experience

The security design only matters if people keep it installed. These are the rules for the parts a person touches.

**Quickstart is fifteen minutes with Tailscale already installed, measured, and the docs give the number without it too.** Run the compose file, run `totem-issuer init`, paste one command on the laptop. `init` on the issuer is a wizard that writes the config (trust domain from the hostname, built-in file provider by default with its loud warning, secrets asked for per enabled bridge) and every question has a flag so headless and scripted setups never block. The compose file ships with the image.

**Secrets are asked for when a bridge needs them.** `totem-issuer bridges enable claude` prompts for exactly what that bridge needs. `secrets set` is for rotation.

**`totem init` detects, shows, and confirms.** It detects which Claude variant applies from Claude Code's own credential state and confirms in one question; when both an OAuth login and an API key are present it explains the difference in two lines and asks rather than guessing. It checks with the issuer that the bridge it's about to wire is enabled there, and if not says so with the exact `totem-issuer bridges enable` command to run. The variant explanation ends with the reassurance that `claude` is used the same way either way. It prints the presence table it's about to write and lets the user edit it. It collects every refusal (interpreter-wrapped tools, static keys found nearby) into one checklist with the exact fix command for each. It ends by telling the user they'll see a fingerprint prompt naming a tool the first time that tool needs credentials, and that a prompt for a tool they didn't run is the signal to check `status`.

**`init` is reversible.** It keeps a manifest of every config line it wrote. `totem uninstall` diffs each surface against the manifest, restores lines that are unchanged since `init`, shows any line the user edited afterwards and asks, removes the socket and launch agent, and offers to revoke the device.

**Refusals are never silent.** Calling tools swallow helper stderr, so a refused exchange or a pending presence prompt also fires a native notification (macOS notification center, `notify-send` on Linux) with the one-line reason and the fix command, and writes to a local `totem log` that `status` surfaces first. Where no notification path exists (headless Linux over SSH), the helper writes `~/.totem/last-error` and the optional one-line shell prompt hook `init` offers shows it once at the next prompt, by stat only, never a parse; the hook is in the manifest so `uninstall` removes it. `totem log` records refusals, prompts, and failures by default; successes are counted, not listed, and `--verbose` opts into the full local record. Presence prompts time out at sixty seconds with a failure that names the tool. `totem trust` with no argument shows what changed and re-pins it.

**No SPIFFE vocabulary in user-facing output.** Identity, your issuer, verified, confirm it's you. The spec terms live in docs and `--verbose`.

**Errors are typed for machines and plain for humans.** Calling tools rarely forward a helper's stderr, so the file is the contract and the exit code is the fast path. Every helper writes `~/.totem/last-error` as JSON (`reason`, `retryable`, `retry_after`, `parked_id` when applicable) on any failure, and exits with distinct codes for retryable (issuer unreachable, step-up pending) versus terminal (revoked, out of grant, attestation failed). A harness that can only see "unable to locate credentials" from aws can still cat a known path and branch. `totem run` performs the backoff itself for anything it wraps. "Issuer unreachable" includes the issuer address and when it was last reached. `doctor` checks reachability first. The quickstart recommends Tailscale so a laptop at a coffee shop still reaches its issuer.

**Command surface fits on one screen.** Agent top level: enroll, init, status, doctor, trust, run, log, uninstall. Device administration under `totem devices`: list, approve, revoke, grant-admin, revoke-admin, allow-unattended. Agent delegation under `totem agents`: grant, renew, revoke, list, and approve for parked step-up requests. Issuer verbs stay on the issuer binary. A second device prints the exact `totem devices approve` command to run on an existing one, and its own `enroll` completes on its own once approved.

**Day two is documented before day one.** A "Losing a device" page covers lost laptop, second laptop, last-admin lockout, and issuer box loss as numbered procedures, linked from the README. `issuer init` offers to schedule a daily backup and issuer `status` shows the age of the last one. `status` on the laptop shows today's proxy usage against the cap, and `init` prints the cap defaults.

## Algorithms and FIPS

ECDSA P-256 for device keys and SVIDs, P-384 for the CA. No Ed25519. Built with the FIPS Go crypto module; in FIPS mode the issuer refuses non-approved configuration.

## Deployment and distribution

- Laptop: single Go binary, no cgo except the macOS platform layer (Secure Enclave and LocalAuthentication are only reachable through Apple frameworks), static everywhere else, from the existing `infamousjoeg/homebrew-tap`. Notarized under the existing Apple Developer account from the first release; that Team ID is what totem pins for its own self-check.
- Broker: single container. One compose file brings up the issuer, the OIDC discovery provider, and Octo STS. Release gate: issuer rebuilt from backup on a fresh box in under ten minutes, measured.
- GitHub Releases with Sigstore signatures and SLSA provenance. Reproducible builds.
- Compatibility: agent N works with issuer N and N+1; issuer refuses agents older than N-1. Forward-only migrations on start.
- Default deny in every policy file shipped.

## Repo

`github.com/infamousjoeg/totem`. Single Go module. `cmd/totem` is the agent, `cmd/totem-issuer` is the broker. Shared code for the Summon protocol, SPIFFE types, and the presence assertion format. Apache 2.0, DCO sign-off, no CLA.

## Scope

**v1:** standalone issuer, macOS and Linux agent, presence gating with grants, shadow grants, and step-up, admin-signed policy, TPM attestation, both Claude variants, AWS Roles Anywhere, GitHub via Octo STS, Summon-protocol secrets, backup and restore, `doctor`, `status`, `revoke`.

**v1.x, each its own release:** SPIRE mode. SSH certificate bridge. Windows agent with TPM. Linux `run` escape hatch. Generic OIDC exchange configurable without code.

**Never:** fleet management, policy planes, org audit, hosted issuer, dev mode, interpreter-wrapped tool attestation, model allowlists in the proxy.

## Sequencing

1. Agent core: enrollment with cert pinning, device key, presence assertion, Workload API, attestor with pin plus Team ID plus parent walk. Conformance against go-spiffe and spiffe-helper in CI.
2. Issuer core: CA hierarchy, passkey admin, enrollment approval, bundle endpoint, presence policy, Summon-protocol secrets, backup and restore.
3. Claude bridge, proxy variant then injection variant. This is the demo.
4. AWS bridge. This is the reason people stay.
5. Octo STS integration for GitHub.
6. SPIRE mode.

Before step 1 (done): Claude Code Team ID and signing identifier verified and cataloged; `github.com/infamousjoeg/totem` is free. Still open: formula and domain names. Before step 3: verify how Claude Code spawns apiKeyHelper (direct or via shell), whether it scrubs `CLAUDE_CODE_OAUTH_TOKEN` from child environments, and whether it honors a setup-token in its Keychain format. Before step 4: verify totem's certificate profile against Roles Anywhere requirements, confirm the SAN URI condition key for policy pinning, and confirm which CA must sign the CRL (if the offline root must, the intermediate becomes the trust anchor). Release workflow pins the Go toolchain and macOS SDK; the self-check compares against the signed release manifest.

See totem-design-decisions.md for the reasoning behind each choice and the alternatives rejected.
