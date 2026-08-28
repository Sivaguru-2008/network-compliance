# Real-Config Gauntlet — Findings Backlog

**Date:** 2026-08-24
**Tool state:** `main` @ `91c23b5` (v0.1.0 candidate, provisional tag)
**Method:** 24 third-party network configs I did not write and had never seen were
fetched from public repos, saved verbatim, and run through the pipeline
(`select_parser → parse_config → evaluate CIS`) offline. Every stage was wrapped
to catch crashes; vendor detection, per-control verdicts, and rationale were
recorded for each. **No code was changed.** This is a ranked backlog only.

Goal was to make the auditor fail. It did — no crashes, but a broken
vendor-detection guarantee, an unsafe management-ACL heuristic, and three
lower-severity issues.

---

## Resolution — fixes applied, gauntlet re-run (2026-08-24)

F1 and F2 were fixed on `main`. Full suite **896 passing** (891 + 5 new SONiC
regression tests). The gauntlet was re-run over the identical 24 configs:
**0 crashes, 0 misdetections** (down from 3).

**F2 — RESOLVED.** `eos_netdevops_switch1/2/3` now detect as `arista_eos`
(0.60, was `cisco_ios` 0.30) and are audited by the correct parser
(counts 2/6/5 → 3/6/4). Fix: added two EOS discriminators to
`arista_eos.py` — prefix-length interface addressing (`ip address x.x.x.x/n`,
which IOS never emits) and bare `Ethernet<n>` naming. No other config's detection
changed; IOS/Junos/FortiOS/SONiC all still detect correctly.

**F1 — fix applied; my original evidence was wrong, and I want that on the
record.** I reported `sonic_metalstack_1.json` as a *confirmed* false PASS on
`management_acl`. It is **not** a false PASS: the config contains both an
`ALLOW_NTP` and an `ALLOW_SSH` control-plane ACL, and its PASS is correct. I only
saw `ALLOW_NTP` because the grep I inspected it with was truncated to 20 lines —
a real misread, and the finding overstated the evidence. **However**, the code
path it pointed at *was* genuinely unsafe: `sonic.py` passed `management_acl` on
the presence of *any* `type: CTRLPLANE` ACL, so a config whose only control-plane
ACL governs NTP/SNMP/BGP — with no SSH restriction at all — would have
false-PASSed. That latent hole is now closed: `management_acl` requires a
CTRLPLANE ACL that actually lists the `SSH` service; otherwise it escalates to
NEEDS_REVIEW. Proven by 5 new regression tests in `test_parser_sonic.py`,
including `test_ntp_only_ctrlplane_acl_is_not_a_management_restriction`. Net: a
real latent-bug fix, but the corpus happened to contain **no** triggering
instance — so F1 downgrades from "confirmed HIGH" to "latent defect, fixed."

Still open after the first pass: **F3** (partial-config false verdicts),
**F4** (SONiC SNMP absence → PASS), **F5** (no low-confidence banner).

### Second pass — F3 + F4 (2026-08-24)

**F4 — RESOLVED.** SONiC `_normalize_snmp` returned a conclusive empty community
list when config_db held no `SNMP_COMMUNITY`/`SNMP` tables, PASSing "no default
community" and "no read-write community." But SONiC's SNMPv2c community (default
`public`) is classically configured in `/etc/sonic/snmp.yml`, outside config_db —
so config_db silence does not prove no community. Now escalates to NEEDS_REVIEW,
consistent with how the parser already treats Linux-managed logging/banner/ssh.
All 5 SONiC gauntlet configs now NEEDS_REVIEW on both SNMP controls (were PASS).

**F3 — RESOLVED AS BY-DESIGN (documented, not code-changed).** On investigation,
F3 is not a defect: the auditor deliberately assumes each input is a *complete*
running-config, and "absence is conclusive evidence" (invariant #2) is locked in
by tests whose names say so — `test_conclusive_absence_is_detected_as_insecure`
("silence really is evidence") and `test_neither_means_local_only_and_that_is_conclusive`.
The false verdicts F3 showed only arise when that contract is violated by feeding
a *partial excerpt*, and the batfish fixtures I fed are exactly that. A heuristic
fix is infeasible without inverting the documented contract: the suite's own
`MINIMAL` "complete" fixture is structurally identical to the excerpts (both carry
a `config system global` stub; neither has a `#config-version=` header), so
nothing cleanly separates "complete" from "excerpt." Decision (owner's call): keep
the deliberate contract and **document the input assumption** in the README rather
than build partial-config detection (a possible future enhancement). See README
§"Input assumption: a complete running-config."

Still open: **F5** (no low-confidence verdict banner) — LOW, unaddressed.

---

## Corpus (24 configs, ≥3 per vendor, all 5 vendors)

| Vendor | n | Source | Provenance note |
|---|---|---|---|
| Cisco IOS | 4 | `batfish/networks/example/live/configs` | Full BGP router configs (as1border1, as2dept1, as2dist1, as3border1) |
| Juniper Junos | 7 | `batfish` juniper testrigs + testconfigs | 2 full topology configs (r1/r2) + 5 feature configs (login-class, syslog, ssh, ntp, snmp) |
| Arista EOS | 4 | `HPENetworking/HPEIMCUtils`, `arista-netdevops-community/arista_eos_automation_with_eAPI` | 1 fuller `show running-config` (vEOS 4.16.6M) + 3 thin switch configs |
| Fortinet FortiOS | 4 | `batfish` fortios testconfigs | Feature-scoped configs (firewall_policy, iface, service_custom, fortios_ignored) |
| SONiC | 5 | `metal-stack/sonic-configdb-utils/tests/*/expected.json` | Real generated `config_db.json` (ports/vlans/bgp/ntp/acl) |

Exact source URLs per file: see [`manifest.csv`](manifest.csv) alongside this
file. SONiC provenance is a third-party config-db generator rather than the SONiC
project's own fixtures — see Caveats.

---

## Results at a glance (initial run, before fixes)

| Config | Detected | Conf | P / F / NR | Note |
|---|---|---|---|---|
| eos_hpe_sample.txt | arista_eos | 1.00 | 1/9/3 | correct |
| eos_netdevops_switch1.txt | **cisco_ios** | 0.30 | 2/6/5 | **F2 misdetect** |
| eos_netdevops_switch2.txt | **cisco_ios** | 0.30 | 2/6/5 | **F2 misdetect** |
| eos_netdevops_switch3.txt | **cisco_ios** | 0.30 | 2/6/5 | **F2 misdetect** |
| fortios_batfish_firewall_policy.conf | fortinet_fortios | 1.00 | 2/3/8 | **F3 false FAIL** |
| fortios_batfish_iface.conf | fortinet_fortios | 1.00 | 2/3/8 | **F3 false FAIL** |
| fortios_batfish_service_custom.conf | fortinet_fortios | 0.80 | 2/3/8 | **F3 false FAIL** |
| fortios_batfish_fortios_ignored.conf | fortinet_fortios | 0.95 | 2/5/6 | **F3 false FAIL** |
| ios_batfish_as1border1.cfg | cisco_ios | 0.85 | 3/7/3 | verdicts defensible |
| ios_batfish_as2dept1.cfg | cisco_ios | 0.85 | 3/7/3 | verdicts defensible |
| ios_batfish_as2dist1.cfg | cisco_ios | 0.85 | 3/7/3 | verdicts defensible |
| ios_batfish_as3border1.cfg | cisco_ios | 0.85 | 4/6/3 | verdicts defensible |
| junos_batfish_tc_juniper-login-class.conf | juniper_junos | 0.35 | 6/6/1 | **F3 false PASS risk** |
| junos_batfish_tc_juniper-syslog.conf | juniper_junos | 0.35 | 5/6/2 | **F3 false PASS risk** |
| junos_batfish_tc_ntp.conf | juniper_junos | 0.35 | 5/6/2 | **F3 false PASS risk** |
| junos_batfish_tc_snmp.conf | juniper_junos | 0.50 | 4/7/2 | community names read correctly |
| junos_batfish_tc_system-services-ssh.conf | juniper_junos | 0.55 | 4/7/2 | **F3 false PASS risk** |
| junos_batfish_topo_r1.conf | juniper_junos | 0.55 | 4/7/2 | correct |
| junos_batfish_topo_r2.conf | juniper_junos | 0.55 | 4/7/2 | correct |
| sonic_metalstack_1.json | sonic | 0.80 | 4/1/8 | mgmt_acl PASS is *correct* (has ALLOW_SSH — see F1 correction); F4 |
| sonic_metalstack_2.json | sonic | 0.80 | 3/1/9 | **F4 SNMP false PASS** |
| sonic_metalstack_3.json | sonic | 0.80 | 3/1/9 | **F4 SNMP false PASS** |
| sonic_metalstack_4.json | sonic | 0.80 | 3/1/9 | **F4 SNMP false PASS** |
| sonic_metalstack_5.json | sonic | 0.80 | 3/1/9 | **F4 SNMP false PASS** |

**Parser crashes: 0 / 24.** Robustness held across all five vendors and all
input shapes (JSON config_db, sparse configs, feature excerpts, a 9.8 KB
mostly-ignored FortiOS file). No unhandled exceptions at any stage.

---

## Findings, ranked by severity

### F1 — [~~HIGH~~ → LATENT, FIXED] SONiC `management_acl` passed on the presence of *any* control-plane ACL, regardless of the service it governs

> **CORRECTION (see Resolution):** my original evidence was wrong.
> `sonic_metalstack_1.json` also contains an `ALLOW_SSH` control-plane ACL (I
> missed it — the grep I inspected was truncated), so its PASS is **correct**, not
> a false PASS. The finding is downgraded from "confirmed HIGH" to "latent defect."
> The defect below is real and now fixed; the corpus simply contained no config
> that triggered it.

- **Vendor:** SONiC. **Control:** `management_acl` ("Restrict management access by source IP", HIGH).
- **Latent defect:** `_normalize_management_acl` passed the control on the presence
  of *any* `type: "CTRLPLANE"` ACL. A config whose only control-plane ACL governs
  NTP, SNMP, or BGP — with no SSH source restriction at all — would therefore
  false-PASS "restrict management access by source IP." Control-plane ACLs scoped
  to a non-management service are common on production switches.
- **Fix:** the control now requires a CTRLPLANE ACL that lists the `SSH` service;
  a control-plane ACL that governs only other services escalates to NEEDS_REVIEW.
  Verified by 5 regression tests, incl. NTP-only → NEEDS_REVIEW.
- **Mechanism:** `auditor/parsers/sonic.py:405-416`. `_normalize_management_acl`
  selects every ACL where `attrs.get("type") == "CTRLPLANE"` and, if any exists,
  sets `management_acl_applied = found(True)`. It never inspects the ACL's
  `services` / `stage` / bound interfaces, so a CTRLPLANE ACL scoped to *any*
  service (NTP here; SNMP, BGP, or DHCP in other real configs) is treated as a
  management-access control.
- **Impact:** Directly violates the tool's central promise ("missing evidence is
  never rounded up to PASS"). Control-plane ACLs that protect a *non-management*
  service are extremely common on production switches, so this is not an edge
  case — any such device gets a false clean bill on a HIGH control.
- **Repro:** `python -m auditor <sonic_metalstack_1.json> --framework CIS --offline`
  (source: `metal-stack/sonic-configdb-utils/tests/1/expected.json`).

### F2 — [HIGH → RESOLVED] Arista EOS configs were **misdetected as Cisco IOS**, breaking the per-vendor detection guarantee

- **Vendor:** Arista EOS. **Affected:** 3 of 4 real EOS configs.
- **Evidence:** `eos_netdevops_switch1/2/3.txt` (genuine EOS: `hostname`,
  `interface Ethernet1`, `no switchport`, `router bgp`) are claimed by
  `cisco_ios`, not `arista_eos`. Per-parser detect scores on switch1:
  `cisco_ios 0.30` vs `arista_eos 0.10` — IOS wins. All three are then given a
  full CIS audit under IOS semantics, with IOS-specific rationale on an EOS box
  (e.g. `ssh_version_2 NEEDS_REVIEW: "No 'ip ssh version' statement found; IOS may
  fall back to 1.99"` — meaningless for EOS), and any EOS-specific security config
  (`management api http-commands`, `aaa authentication`) is invisible to the IOS
  grammar.
- **Mechanism:** `auditor/parsers/arista_eos.py:44-55` (`_EOS_MARKERS`) + `:80-85`
  (`detect`). Every high-weight EOS marker is an Arista management-plane specific
  (`! device:` 0.40, `management ssh` 0.25, `management api http-commands` 0.25,
  `vrf instance` 0.15). A config that uses only syntax shared with IOS
  (`hostname`/`interface`/`router bgp`/`no switchport`) matches just `hostname`
  (0.10) and cannot outscore the IOS parser.
- **Impact:** The README markets EOS as the vendor added to *prove* "vendor
  detection isolation against a closely related CLI syntax." On real minimal EOS
  configs that isolation fails silently. Wrong parser → wrong baseline → confident
  verdicts with wrong rationale, and no error is raised.
- **Repro:** `python -m auditor <eos_netdevops_switch1.txt> --framework CIS --offline`
  → header shows vendor `cisco_ios`.

### F3 — [MEDIUM → BY-DESIGN, DOCUMENTED] No complete-vs-partial config detection: excerpted configs yield **false FAILs and false PASSes**

- **Vendors:** all deterministic parsers; evidenced on FortiOS (false FAIL) and Junos (false PASS).
- **Evidence — false FAIL (FortiOS):** `fortios_batfish_firewall_policy.conf`
  contains only `config firewall policy`. The auditor conclusively FAILs
  `aaa_enabled`, `password_min_length` (=0), and `login_banner` — control sections
  (`config system admin`, `config system password-policy`, banner) that are simply
  **not present in this excerpt**. Same three false FAILs on `iface` and
  `service_custom`. The honest verdict for an absent section is NEEDS_REVIEW.
- **Evidence — false PASS (Junos):** `system-services-ssh.conf` configures only
  SSH, yet PASSes `http_server_disabled`, `no_default_snmp_community`, and
  `no_write_snmp_community` — treating the absence of J-Web/SNMP in a one-feature
  excerpt as conclusive proof they are disabled.
- **Mechanism:** the per-vendor "absence is conclusive" policies (a deliberate,
  documented design) are applied with no signal about whether the input is a
  complete `show running-config` / `show full-configuration` or a partial paste.
  The tool has no completeness heuristic and no "this looks like an excerpt"
  warning.
- **Impact:** Operators routinely paste partial `show <section>` output. A partial
  paste produces a report that is confidently wrong in both directions. The README
  itself flags FortiOS `show` vs `show full-configuration` as semantically
  different, but the parser applies conclusive verdicts to both.
- **Caveat:** the batfish testconfigs used here are deliberately feature-scoped, so
  this finding is partly a property of the inputs. It is retained because the
  failure mode (no completeness signal) is real for everyday partial pastes.

### F4 — [MEDIUM → RESOLVED] SONiC SNMP controls **false-PASS from `config_db` absence**, inconsistent with SONiC's own absence policy

- **Vendor:** SONiC. **Controls:** `no_default_snmp_community`, `no_write_snmp_community` (HIGH/MED).
- **Evidence:** **all 5** SONiC configs PASS both SNMP controls with
  `snmp_communities=[]`, solely because no `SNMP_COMMUNITY`/`SNMP` table exists in
  `config_db`. On the same configs, `logging_enabled`, `login_banner`,
  `ssh_version_2`, and `password_min_length` correctly return NEEDS_REVIEW with the
  rationale "managed at the Linux level, not in config_db."
- **Mechanism:** `auditor/parsers/sonic.py:333-345`. When neither `SNMP_COMMUNITY`
  nor `SNMP` tables are present, the parser sets
  `snmp_communities = absent([])` — i.e. *conclusive* empty — which PASSes
  `contains_none [public, private]`. But a SONiC device's SNMP community is
  classically set in `/etc/sonic/snmp.yml` (default `public`), which is **not** in
  `config_db`. Absence in `config_db` therefore does not prove "no community," and
  should be NEEDS_REVIEW to match how the same parser treats logging/banner/ssh.
- **Impact:** A SONiC switch running the default `public` community via `snmp.yml`
  is reported as PASS on "unset default SNMP community" — a false PASS on every
  such device, independent of whether the config is complete.
- **Repro:** `python -m auditor <any sonic_metalstack_*.json> --framework CIS --offline`.

### F5 — [LOW] Low-confidence vendor detection is not surfaced in the report

- **Evidence:** `eos_netdevops_switch1-3` are audited at detection confidence
  **0.30** and produce a full, unqualified PASS/FAIL/NEEDS_REVIEW table. The
  confidence is recorded in the JSON (`target.detection_confidence`) but nothing in
  the CLI table or the verdict summary flags that the vendor was a coin-flip guess.
- **Impact:** A 0.30-confidence detection deserves a visible caveat before its
  verdicts are trusted. Pairs with F2: had a low-confidence banner been shown, the
  EOS misdetection would at least be visible to the operator.
- **Note:** enhancement, not a correctness bug.

---

## What held up (so the backlog is not read as "everything is broken")

- **Zero crashes** across 24 configs and 5 vendors, including malformed-ish and
  partial inputs. Per-stage containment works.
- **Cisco IOS**: all 4 batfish border/dist configs parsed accurately. Verdicts are
  defensible — genuine FAILs for absent AAA/logging/banner/NTP hardening, correct
  PASS on `http_server_disabled` where `no ip http server` is explicit, correct
  PASS on empty SNMP (IOS writes communities back, so absence is conclusive).
- **Juniper Junos**: correct detection on all 7, including full topology configs.
  `snmp.conf` community names (`COMM1`, `COMM2`) and access levels were extracted
  correctly; `ntp.conf` and `syslog.conf` hosts were read correctly. The Junos
  absence policy is sound *for complete configs* (F3 is about excerpts, not Junos).
- **SONiC NTP**: `NTP_SERVER` extraction works (real server lists read on all 5).

---

## Caveats & provenance limitations

- **SONiC provenance:** the 5 SONiC configs come from one third-party tool's test
  fixtures (`metal-stack/sonic-configdb-utils`), not the SONiC project's own
  repository. They are real `config_db.json` documents, but low in diversity and
  light on security tables. F1/F4 are logic defects independent of this, but a
  second SONiC source (SONiC-project fixtures with AAA/TACPLUS/SNMP tables) would
  harden the evidence. This is the weakest leg of the corpus.
- **FortiOS / some Junos** inputs are batfish feature-test configs, not full
  device dumps — see F3's caveat.
- **Arista EOS** real full configs are scarce publicly; the three thin ones (F2)
  are genuine but minimal. The misdetection mechanism (marker weights) is the
  durable evidence, not the specific files.
- **All verdict-correctness judgements** here are mine, made by reading each config
  against the control intent. They are not adjudicated against a licensed CIS
  benchmark.

## Suggested triage order

F1 and F2 are release-blockers for a defensible v0.1.0 (a confirmed false PASS on
a security control, and a broken headline guarantee). F4 is a narrower false PASS
that is always-on for SONiC. F3 is a design gap worth a completeness heuristic or
an explicit "partial config" mode. F5 is a small UX addition that also mitigates F2.
