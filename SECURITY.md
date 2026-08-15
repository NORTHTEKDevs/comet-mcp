# Security & authorized-use

`comet-mcp` drives a real, logged-in browser. Some of its capabilities touch credentials. This
document is deliberately blunt about what those capabilities are, what they never do, and the terms
under which you may use them.

## Authorized use only

This software is for driving **your own browser** and **accounts you own or are explicitly authorized
to administer** (e.g. a client account you manage under an agreement that permits automated access).
Using it against accounts you do not own or are not authorized to access may be illegal. You are
responsible for how you use it. The authors provide it as-is, with no warranty, and accept no
liability for misuse. If you are not certain you are authorized, do not enable the credential or
mission features.

## What the credential features do - and do not do

The advanced features are **off by default** and **opt-in per session**. A default session cannot do
any of the following.

- **Read the local saved-password vault** (`comet_credential_use`, `comet_credential_reveal`). This
  uses Windows DPAPI, which can only decrypt the *current OS user's own* Chromium vault. It cannot
  decrypt anyone else's vault, on this machine or any other. There is no remote component.
- **Never exfiltrates.** A decrypted password is typed into a field in the local browser, or (for
  `reveal`, which requires its own stronger opt-in) returned to the local caller. It is **never**
  written to a log, an audit record, an error message, or the network. The audit log records that a
  credential was used for a site, plus the approval id - never the value.
- **Every credential operation requires four independent gates**, all of which must pass: (1) the
  site is pre-authorized in the session policy; (2) the browser's current page origin equals that
  site; (3) a single-use, time-bounded approval that a human granted out-of-band (a CLI the agent
  cannot invoke); and (4) the browser's own origin-bound autofill. `reveal` adds a fifth: a distinct
  approval type, so a fill/use approval can never authorize a reveal.
- **`SUBMIT` is opt-in.** By default the agent fills a login and a human submits it.

## Unattended missions

Unattended runs (`comet_begin_mission`) require an **Ed25519-signed, scoped, single-use mission
grant** that a human issues out-of-band. The agent cannot mint or widen one. A mission is bound to a
single account and a fixed set of domains, actions, and budgets; it is structurally unable to act
outside that scope. It carries a kill switch (checked before every action), hard action/time
budgets, a tripwire that halts on repeated out-of-scope attempts, and a block-and-pause gate on
irreversible-looking actions.

## Honest limits (this is not magic)

- **An agent that holds both a password and a 2FA code is, by construction, a single point of total
  compromise for every account in a mission's scope.** The containment scopes and records misuse; it
  cannot make the agent itself un-compromisable. Run unattended missions with a human as the backstop
  and keep scopes tight.
- **Secret redaction and irreversible-action detection are heuristics.** They cover the common cases
  and are adversarially tested, but a novel secret format or an unusually-named destructive button
  can slip through. Treat `allow_unredacted_inspect` and `--preauthorize` as deliberate decisions.
- **Prompt injection is contained, not eliminated.** The dual-LLM split and egress gate raise the
  cost sharply and bound the blast radius; they do not make injection impossible.

## Recommended posture

- Prefer **session reuse** (stay logged in; reuse the live session) over reading the vault. Most
  tasks need no plaintext credential at all.
- Keep mission scopes minimal - one account, the fewest domains and actions that get the job done.
- Keep the signed audit log; it is your record of exactly what ran in an account.

## Reporting a vulnerability

Email **security@northtek.io** (or info@northtek.io). Please do not open a public issue for a
security report.
