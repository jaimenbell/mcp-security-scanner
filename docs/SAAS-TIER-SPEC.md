---
title: "MCP Security Scanner — Recurring ('Continuous Watch') Tier Spec"
type: spec
status: spec-only-DECISION-PENDING
audience: operator (build/no-build decision)
version: 2026-07-22
author: Opus spec lane (lane/saas-spec)
grounded_in: "PRODUCT.md, staged/sales-kit/pricing-tiers.md, docs/CLIENT_ONE_PAGER.md, mcp_scanner/cli.py, LICENSE"
repo_state: "master @ 78fd2fb, 155 passed / 7 skipped (verified 2026-07-22), MIT + PUBLIC"
tags: [mcp-security-scanner, spec, saas, pricing, recurring-tier]
---

# Recurring Tier Spec — "Continuous MCP Watch" ($99–149/mo)

> [!info] What this document is
> A **spec only**. No code was written. It exists so the operator can decide
> *whether and when* to build the recurring tier, and — if yes — hand a build
> lane a ready acceptance contract. Everything here is anchored to the
> operator's hard constraints: **solo builder, $0 infra-budget preference,
> hard guardrail against unattended spend, client source code is sacrosanct,
> hold zero client credentials, and this must never become pager duty.**

> [!warning] The one fact that shapes everything below
> The core scanner is **MIT-licensed and the repo is PUBLIC** (`LICENSE`,
> copyright Jaime Bell). A client can clone it and run
> `python -m mcp_scanner.cli <path> --fail-on P1` in their own CI **for $0,
> forever, legally.** So the recurring tier **cannot gate the scanner binary.**
> It can only sell the *service wrapped around* it. Any pricing story that
> pretends otherwise will not survive a technical buyer. This spec is built
> around that truth, not against it.

---

## 0. TL;DR recommendation

**Build shape (a): a client-side GitHub Action + pre-commit hook.** The scan
runs inside the *client's* CI; their source never leaves their machine; the
operator holds no credentials and no code. The recurring subscription sells
three things the open core cannot give away: **(1) a private premium
detector pack** (open-core split, access-revocable = license enforcement),
**(2) a monthly human-triaged digest** of net-new findings against a
per-client baseline (the honesty/anti-wolf-crying value), and **(3) rule
freshness + a human to ask** as MCP threats evolve. Shape (b)
(operator-side scheduled scans) is a viable fallback but takes on
credential-custody and code-custody burden the operator explicitly wants to
avoid. Shape (c) (hosted service) is the wrong build at this stage — say no.

**Minimum sellable increment (this month, ~3–5 build-days):** ship the
GitHub Action + a documented onboarding + a monthly-digest commitment, and
close the first customer on **managed triage alone** — the private detector
pack can land in a fast-follow. See §4.

---

## 1. Delivery-shape options, honestly costed

All three assume the same engine (already built: `mcp_scanner`, 7 detector
families, reachability + taint grading, `--fail-on`, `--client-report`,
`--json`). They differ only in **where the scan runs** and therefore in
**what the operator has to hold and operate.**

### Shape (a) — Client-side GitHub Action / pre-commit hook  ⭐ RECOMMENDED

**How it works.** The client adds a ~10-line workflow (or a `.pre-commit-config`
entry) that installs the scanner and runs `--fail-on P1` on push and on a
weekly schedule. A P0/P1 regression fails *their* build. The client's CI
uploads the `--client-report` markdown as a build artifact **on their side**.
The only thing that optionally reaches the operator is a **counts-only
summary** (e.g. "3 findings, 1 P1, 2 P3 — repo X, commit abc123") via a
webhook the client configures — or *nothing at all* in the leanest MVP,
where the client simply forwards their CI summary.

| Dimension | Assessment |
|---|---|
| Operator infra | **Near-zero.** No server, no DB, no scheduler. An optional counts-webhook receiver can be a free serverless function or a Discord/Slack incoming webhook (operator already runs discord-mcp). MVP can ship with *no receiver*. |
| Client source custody | **None ever.** Source stays on the client's runner. This is the strongest possible answer to "your code is sensitive." |
| Credentials held | **None.** Operator holds no client tokens. |
| Pager-duty risk | **None.** The Action runs in the client's CI; failures page the *client's* team, not the operator. |
| Ongoing burden | Monthly triage of net-new findings (est. **≤30 min/client/month**, §3) + rule-pack updates on the operator's own cadence. |
| Weakness 1 — license enforcement | The public core is free (MIT). Enforcement lives entirely on the **private detector pack** (§2) via access-revocation, not on the core. |
| Weakness 2 — update distribution | Clients pin a version; pushing rule updates means the client bumps a pin or the Action tracks a tag. Solvable with a pinned Action tag + a "we cut a release monthly" cadence (§2). |

**Why it wins for this operator:** it is the *only* shape that satisfies all
five hard constraints simultaneously (zero infra, zero creds, zero code
custody, no pager duty, code-privacy-perfect). Every other shape trades one
of those away.

### Shape (b) — Operator-side scheduled scans via granted read access

**How it works.** The client grants the operator **read-only** access to
their repo (a deploy key or a fine-scoped GitHub read token). A scheduled job
on the operator's machine (Windows `schtask`, the pattern the operator
already uses fleet-wide) clones/pulls and runs the scanner, then emails a
digest.

| Dimension | Assessment |
|---|---|
| Operator infra | **Light** — one `schtask` + a per-client token store. Still $0. |
| Client source custody | **Operator now holds a clone of the client's source** on their machine → custody liability, and the single worst outcome if the machine is compromised (§3). |
| Credentials held | **A read token per client.** Even read-only, this is a credential to secure, rotate, and revoke — exactly the "hold zero client credentials" line the operator drew. |
| Pager-duty risk | Low-moderate — a failing scheduled job is the operator's problem to notice and fix (it *is* the operator's infra). |
| When it's actually the right call | If a client **cannot** or will not add CI (no GitHub Actions, air-gapped, non-GitHub host). Keep it as a **named fallback**, not the default. |

**Verdict:** viable but it imports precisely the two burdens (credential
management + code custody) the operator wants to avoid. Offer only when
shape (a) is impossible for a specific client.

### Shape (c) — Hosted multi-tenant service

Client uploads/connects a repo to a web dashboard the operator hosts and
runs. This requires: a hosted web app + auth + a database + background
workers + billing integration + **accepting client source onto operator
infrastructure at scale** + the security posture to justify that custody.

**Verdict: wrong build at this stage — do not build it now.** It maximizes
every burden the operator is minimizing (infra spend, unattended compute,
code custody, on-call surface) and its only advantage — a slick dashboard —
is a *marketing* differentiator the honest-CLI brand does not need to win a
first customer. Revisit only after ~5+ paying watch customers make the
operational load worth productizing, and even then a thin CI-results
aggregator beats a code-custody dashboard.

---

## 2. Licensing & packaging — what the paid tier *actually* gates

> [!danger] The core is MIT + public. You cannot re-gate what you already
> published. Be honest about this in every sales conversation.

**What is NOT defensible to gate:** the 7 shipped detectors, the
reachability/taint passes, `--fail-on`, and `client_report.py` — all already
public and MIT. A client can run them free. Selling "access to the scanner"
as the subscription is not credible and the brand's whole differentiator is
honesty; don't torch it here.

**What IS defensible to sell (the actual subscription value):**

1. **Private premium detector pack (open-core split).** Create a *separate*
   private repo, e.g. `mcp-scanner-pro`, holding detectors and curated rules
   that are **not** in the public core — candidates already named in
   `PRODUCT.md`'s remaining-gap list: deeper/cross-repo taint, JS/TS AST
   parity, an Express/Fastify auth-posture detector, git-history secret
   scanning (gitleaks fold-in), and a curated MCP-threat rule set with a
   suppression/baseline file. License it **commercially/proprietary** (NOT
   MIT). **Enforcement = access:** the client installs it via a private
   repo collaborator invite or a scoped install token; **non-payment →
   revoke access → the premium scan stops working while the free core keeps
   running.** This is clean, $0, and revocable for a solo operator. It is
   the only hard license lever available.
2. **The monthly human-triaged digest.** Static scan surfaces the queue; a
   human separates a real regression from heuristic noise against a
   **per-client baseline** (accepted findings suppressed, so the digest
   shows only *net-new, triaged* items). This is inherently gated by the
   operator's time — impossible to pirate — and is the core anti-wolf-crying
   value the brand is built on.
3. **Rule freshness + support/SLA.** A subscription to "the ruleset stays
   current as MCP threats evolve, delivered as a versioned Action release on
   a stated cadence, and you get a human to email when a finding is
   confusing." Defensible because MCP threats move and a one-time clone goes
   stale.

**Packaging mechanics (build-lane inputs):**
- Publish the core so CI installs it cleanly — today it is `pip install -e .`.
  Choose one: **(i)** publish `mcp-security-scanner` to PyPI (console script
  `mcp-scan` already declared in `pyproject.toml`), or **(ii)** install from a
  **pinned Git tag** in the Action (no PyPI account, no name-squat exposure).
  Recommend (ii) for the MVP to avoid tying the operator's real name to a
  public package before it's warranted (open question Q1).
- The GitHub Action is a thin **composite action** (marketplace repo or a
  documented workflow snippet) that pins a scanner version, runs `--fail-on`,
  uploads the report artifact, and optionally posts the counts summary.
- The pre-commit hook ships as a `.pre-commit-hooks.yaml` in the public repo.

> [!note] Honest one-liner for the sales page
> "The scanner is free and open — clone it and run it yourself anytime. The
> subscription buys you the premium detector pack, a human who triages every
> net-new finding so you never chase a false alarm, and a ruleset kept
> current as MCP threats evolve."

---

## 3. Trust & security model

**Data-flow invariant (shape (a)):**

| Data | Where it lives | Ever reaches operator? |
|---|---|---|
| Client MCP **source code** | Client's CI runner only | **NEVER.** |
| Full **findings body** (file:line + code snippets) | Client's CI artifact, client-side | Only if the client *chooses* to paste specific net-new findings for triage. |
| **Counts summary** (N findings, severities, repo, commit SHA) | Optional webhook | Only if client enables it. Contains **no code**. |
| Client **credentials** | — | **NEVER held.** |
| What the operator holds | Client contact, subscription status, finding *metadata/trend* (counts over time), and any snippets the client voluntarily shared for triage | Metadata only by default. |

**Transmission/storage rules the build must enforce:**
- The Action's only egress is the counts-summary webhook; a test must assert
  the summary payload contains **no source snippets** (see gate §6-G5).
- The `--client-report` artifact is uploaded to the **client's** artifact
  store, never POSTed to the operator.
- The private detector pack, when run, executes on the **client's** runner
  too — the pack is *code the client pulls*, not a service the operator hosts;
  it also never exfiltrates source.

**Incident story — "the operator's machine is compromised":**
- **Shape (a) blast radius:** attacker gets the **private detector-pack
  source** (commercial-value loss, not client harm) + **finding metadata**
  (low sensitivity: "client X had 2 P1s in March") + client contact list.
  **Client source cannot leak because it was never there.** Remediation:
  rotate the pack's distribution token, cut a new pack version, notify
  clients of the metadata exposure. No client-source breach to disclose.
- **Shape (b) blast radius (for contrast, why (a) wins):** attacker gets
  **read tokens to every client repo** *and* **local clones of client
  source** → a real client-source breach requiring disclosure to every
  client. This is the outcome shape (a) structurally eliminates.

This asymmetry is itself a **sales asset**: "I designed the watch so that
even if my laptop is stolen, your source was never on it."

---

## 4. Effort estimate + minimum sellable increment

**Minimum sellable increment (close a $99/mo customer THIS month):**
The GitHub Action (or even a hand-delivered workflow snippet) running the
**already-built** scanner on the client's push + weekly schedule, **plus a
written commitment to a monthly human-triaged digest.** Sell it as
**"Managed MCP Watch"** on *managed triage alone* — the private detector
pack is a fast-follow, not a blocker. Everything the MVP needs to *scan* is
done (155 tests passing, verified 2026-07-22); the MVP work is packaging +
onboarding docs + the digest template, not engine work.

**Build plan, model-routed** (routing per operator's model-routing-v2:
Sonnet executes packaging boilerplate; Opus authors the commercial license +
the access-revocation runbook = irreversible/legal blast radius; verify the
license-gate back on Opus):

| Increment | Scope | Est. | Model routing |
|---|---|---|---|
| **MVP-1: Action + onboarding** | Composite GitHub Action (pin version, `--fail-on P1`, upload report artifact, optional counts webhook) + `.pre-commit-hooks.yaml` + a client onboarding doc + monthly-digest template + a ≤30-min/client triage runbook | **3–5 days** | Sonnet build; Opus reviews egress-safety gate |
| **FF-2: private detector pack** | Split `mcp-scanner-pro` private repo, ≥1 premium detector not in core, commercial LICENSE, access-token install path, revocation runbook | **4–7 days** | Opus authors license + revocation contract; Sonnet builds the detector + install path; Opus verifies the gate |
| Opt-3: counts-webhook receiver | Free serverless fn or reuse discord-mcp incoming webhook; trend dashboard optional | 1–2 days | Sonnet |
| (defer) Shape-b fallback | schtask loop + per-client read-token store + custody policy | +5–8 days | Opus writes custody policy; Sonnet builds |
| (do-not-build now) Shape-c hosted | — | 4–8 weeks | — |

**Sellable after MVP-1 alone.** FF-2 sharpens the license story but is not
required to invoice the first customer.

---

## 5. Pricing sanity vs `staged/sales-kit/pricing-tiers.md`

The existing kit already prices this as **Tier 2 "CI-Gate Watch" $99–149/mo**
and is admirably honest that today it is "a CI config, not a service" and
"not a continuous-monitoring dashboard." This spec **keeps the $99–149 band**
but **sharpens the value story**, because the bare CI config is free (MIT):

- **Keep the band, change the deliverable label** from "CI gate + monthly
  digest" to **"Managed MCP Watch: your CI runs it + I keep the rules current
  + I triage every net-new finding + premium detector pack + a human to ask."**
  The automation is the *hook*; the human triage + private pack + freshness
  are the *thing being paid for*. Without that reframe, a technical buyer
  correctly notes they can self-run the CLI for $0.
- **Comps still support the band:** Enkrypt AI, Gopher Security, mcpscan.ai,
  MCP Manager all sales-gate pricing; Prowler/JFrog adjacent SaaS sit at
  $99–149/mo (per `PRODUCT.md`). Transparent entrant matches/undercuts. No
  change needed to the band.
- **Optional downsell (operator's call, Q4):** a **$49–79/mo self-serve**
  tier = the public Action + public rules + quarterly rule refresh, **no
  human triage, no private pack**. Lets a price-sensitive buyer self-serve
  while the $99–149 managed tier carries the human value. Adds a second SKU
  to maintain — recommend deferring until a lead actually asks for it.
- **Delivery shape does not move Tier 1 ($250–750 one-shot) or Tier 3
  (fix-it):** those are unchanged. This spec only refines Tier 2.

---

## 6. Acceptance gates for the eventual build lane

A build lane may report done only when **all** of these pass:

- **G1 — Clean install:** the scanner installs and runs in a fresh
  environment with **no `-e .` and no `MCP_SCANNER_FLEET_ROOT`** required for
  a single-repo client scan — via PyPI *or* a pinned Git tag. `mcp-scan <path>
  --fail-on P1` returns exit 2 on a P0/P1 fixture, 0 on a clean fixture.
- **G2 — GitHub Action:** a client adds the watch in **≤10 lines** to
  `.github/workflows/`; it runs on `push` + a weekly `schedule`, fails the
  build on `--fail-on P1`, and uploads the `--client-report` artifact
  client-side. Demonstrated green on a clean fixture repo and red on a vuln
  fixture repo.
- **G3 — pre-commit hook:** `.pre-commit-hooks.yaml` published; a documented
  `.pre-commit-config.yaml` entry runs the scanner locally and blocks a commit
  introducing a P1.
- **G4 — Private pack gate (FF-2 only):** the premium pack lives in a
  separate repo under a **non-MIT commercial license**; with access it adds
  ≥1 detector the free core lacks; **revoking access provably breaks the
  premium scan while the free core still passes.** A test/asserted runbook
  demonstrates the revocation.
- **G5 — Egress safety:** an automated test asserts the counts-summary
  webhook payload contains **no source code / no file-content snippets** —
  only counts, severities, repo name, and commit SHA. The `--client-report`
  is never transmitted to the operator by the Action.
- **G6 — Not-pager-duty proof:** a monthly-digest template + a triage runbook
  that a reviewer confirms is executable in **≤30 min/client/month**, with an
  explicit per-client baseline/suppression mechanism so the digest shows only
  net-new findings.
- **G7 — Licensing doc:** a client-facing doc states plainly what is MIT
  (core), what is commercial (pack), and what the subscription buys (triage +
  freshness + premium rules) — no implication that the open binary is being
  sold.
- **G8 — Regression:** all previously-passing tests still green
  (**155 passed / 7 skipped** baseline, verified 2026-07-22 @ `78fd2fb`),
  plus new tests for G2, G4, G5.

---

## 7. Open questions for the operator

1. **PyPI vs pinned Git tag** for CI install? PyPI is smoother for clients but
   publishes a package under the operator's real name (name-squat + identity
   exposure). Recommend pinned-tag for MVP. **(Q1 — blocks G1 choice.)**
2. **Private detector pack now, or fast-follow?** The MVP can close a customer
   on managed-triage-only. Split `mcp-scanner-pro` now (stronger license
   story) or after the first close (faster to revenue)? Recommend fast-follow.
3. **How much metadata are you willing to hold?** Default is counts-only. The
   *leanest* incident posture holds **nothing** — client self-serves the
   digest, you triage on a screenshare where nothing is stored. Cleaner
   breach story, more manual. Your call on the trade-off.
4. **Add the $49–79 self-serve downsell SKU**, or keep a single $99–149
   managed tier? Recommend single-SKU until a lead asks.
5. **Billing rail** (must be $0-infra, no unattended spend): Stripe Payment
   Link / recurring invoice / manual? Recurring billing needs *a* rail even
   though there's no compute spend concern.
6. **Time budget:** `PRODUCT.md` states this lane must **not** compete with
   the already-fully-allocated weekly outreach hours. Is ≤30 min/client/month
   of triage acceptable against that, and at what client count does it start
   to? (Sets a natural cap on how many watch customers to take before
   productizing triage.)

---

> [!abstract] Bottom line
> The engine is done. The recurring tier is a **packaging + service-design**
> problem, not an engineering one. Ship the client-side Action so the client's
> code never leaves their machine, sell the human triage + private pack +
> freshness (the parts MIT can't give away), and you can invoice a first
> $99/mo customer this month on ~3–5 days of packaging work — with an incident
> story ("your source was never on my laptop") that funded competitors can't
> match.
