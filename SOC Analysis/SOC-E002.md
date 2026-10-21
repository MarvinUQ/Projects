# SOC-E002: Detecting and Closing an RDP Brute-Force Blind Spot

Oct 20, 2026 · @Marvin

*Defense-side record. The attack itself — Hydra's RDP brute force against Win11Lab — is documented in PTest-E002.*

| Field | Entry |
| --- | --- |
| Date | 2026-10-15 to 2026-10-20 |
| Entry | SOC-E002 |
| Description | Blue-team side: triaging the Hydra RDP brute-force attack from PTest-E002 across Suricata, Wazuh, and Windows Event Viewer. The first pass showed a full host-layer detection gap; the investigation traced it to Default Domain Policy, fixed it, and a second pass confirmed full detection across every layer. |
| Tool(s) used | Wazuh, Suricata, Event Viewer, Group Policy Management Console (GPMC), `auditpol`, `gpresult` |
| Who | Marvin, acting as the SOC analyst / defender |
| What | Detection triage of the PTest-E002 attack, a root-cause investigation into a missing host-layer logging gap, the fix, and a confirmation pass |
| When | 2026-10-15 (gap found), 2026-10-15–20 (investigation and fix), 2026-10-20 (confirmed) |
| Where | Home Lab |
| Why | As a cybersecurity learner's practice in triage, root-cause investigation, and verifying a fix against real attack traffic |
| Additional notes | See PTest-E002 for the attack itself: the Hydra command, timing, and attacker-side evidence (Kali terminal, pcaps). |

## Executive summary

- **Overview:** The attack from PTest-E002 was triaged across three detection layers. The first pass (10/15) found a complete host-layer blind spot: Windows Security log and Wazuh showed nothing, while Suricata detected the attack fine. The gap was root-caused to Default Domain Policy and fixed via GPMC. A second pass (10/20), using the identical attack, confirmed full detection across all layers.
- **Impact:** None on the lab itself. The impact of the finding is that, until this fix, every domain-joined machine in the lab was blind to logon events at the host layer.
- **Result:** Network-layer detection (Suricata, SID 2001330) worked in both passes, independent of host configuration. Host-layer detection (Windows 4625/4624, forwarded by Wazuh) was completely absent in the first pass due to an unconfigured Group Policy subcategory, and fully present in the second pass after the fix.
- **Recommendation summary:** Add an account lockout policy, add correlation/threshold detection for repeated failed logons, enable logging on the relevant pfSense rule, correct Wazuh's default MITRE mapping for this event type, and periodically audit Default Domain Policy's audit configuration against a known-good baseline.

## Pass 1 (2026-10-15): the detection gap

### What each layer saw

- **Suricata:** 10 alerts (signature ID 2001330, *ET INFO RDP - Response To External Host*) on interface `enp7s0`, two per TCP session, correlating cleanly to all 5 connection attempts from PTest-E002.
- **Windows Security log / Wazuh:** **nothing.** No 4625 or 4624 events for the attack window, in Event Viewer or in Wazuh, which only forwards what the OS logs.

*(Screenshot: Event Viewer / Wazuh search showing no 4625 results for the attack window)*

This is the core finding of the first pass: the attack was clearly visible at the network layer and entirely invisible at the host layer. The two layers are not redundant — Wazuh's visibility depends entirely on what the OS actually logs, while Suricata reads mirrored traffic directly off the wire, independent of host configuration. One layer having a blind spot didn't affect the other, which is exactly why relying on a single detection layer is risky.

## Root-cause investigation and fix

1. `auditpol /get /subcategory:"Logon"` on Win11Lab confirmed Logon auditing was set to **No Auditing**.
2. The legacy Local Security Policy page (`secpol.msc`) showed the same result, and re-enabling it there appeared to work — but had no effect.
3. `gpresult /r` showed why: **Local Group Policy was explicitly denied**, in favor of **Default Domain Policy**. Any local change on Win11Lab could never take effect, regardless of refresh timing — this wasn't a policy being reset on a cycle, it was a local setting that was never going to apply in the first place.
4. Using GPMC — connected to `lab.local` from Win11Lab, under the domain admin account `mwebb-adm` — the root cause was found directly in Default Domain Policy: `Advanced Audit Policy Configuration > Logon/Logoff > Audit Logon` was set to **Not Configured**.

*(Screenshot: GPMC, Default Domain Policy settings report, Advanced Audit Configuration section)*

*(Screenshot: GPMC, Audit Policies > Logon/Logoff before the fix — Audit Logon = Not Configured)*

**The fix** was applied at the correct level — Default Domain Policy, not the local machine — setting Audit Logon to **Success and Failure**:

*(Screenshot: GPMC, Audit Policies > Logon/Logoff after the fix — Audit Logon = Success and Failure)*

One related setting worth noting: Default Domain Policy also has *"Audit: Force audit policy subcategory settings to override audit policy category settings"* set to **Enabled**. This is what makes the modern, subcategory-level policy (what was just fixed) take precedence over the legacy category-level page — and it explains why `auditpol` is the authoritative source to check, not the legacy GUI.

## Pass 2 (2026-10-20): confirmation

PTest-E002's attack was rerun, identical method, against the same account. This time, the Windows Security log and Wazuh were fully populated:

| # | Time (UTC) | Event | Status / Sub Status |
| --- | --- | --- | --- |
| 1 | 20:06:53.795 | 4625 fail | 0xC000006D / 0xC000006A |
| 2 | 20:06:55.827 | 4625 fail | 0xC000006D / 0xC000006A |
| 3 | 20:06:57.852 | 4625 fail | 0xC000006D / 0xC000006A |
| 4 | 20:06:59.875 | 4625 fail | 0xC000006D / 0xC000006A |
| 5 | 20:07:02.450 | **4624 success** | Logon Type 3, NTLM V2 |

Sub status `0xC000006A` ("unknown user name or bad password") on every failure confirms the account itself was recognized — which is what maps this to **T1110.001, Password Guessing**, rather than the broader T1110. The successful 4624 shows Logon Type 3 (network), Authentication Package NTLM V2, source workstation `kali`, source IP `10.10.0.10`.

The five events are spaced roughly 2 seconds apart, matching Hydra's `-t 1` throttle in PTest-E002 — a timing pattern that is itself a detectable signature, independent of log content.

*(Screenshot: Event Viewer, Security log, the 4625/4624 sequence)*

All three layers — Kali's own output (PTest-E002), Suricata/Wazuh's network alerts, and the Windows Security log — now agree on the same five events, within about a second of each other.

### Secondary finding: Wazuh's MITRE mapping is wrong for this event

Wazuh's built-in rule for these 4625 events (rule ID 60122) maps them to **T1531, Account Access Removal** — which is incorrect; T1531 concerns revoking existing access, not failed authentication attempts. This is a vendor/tooling mapping error baked into Wazuh's default ruleset, not a test artifact. It's a useful parallel to the AI-model hallucination issue being investigated separately with Hermes: automated ATT&CK mapping — whether from a SIEM's bundled rules or an LLM — should be verified against the official technique definitions, not trusted outright.

*(Screenshot: Wazuh dashboard, the 4625/4624 events with `rule.id:60122` and its MITRE mapping visible)*

## Mitigation control

Signature 2001330 is informational and protocol-level only — it fires on *any* RDP response to an external host: a successful brute force, legitimate remote administration, or a port scan that got a banner, alike. On its own it cannot distinguish an attack from normal use; only the pattern (5 connections, same source, \~2s apart) and, with the audit fix applied, the host-side failure/success sequence actually establish that this was an attack.

Host-layer visibility turned out to depend entirely on a single domain-wide Group Policy setting that had never been explicitly configured — one missed subcategory in Default Domain Policy silently blinded Wazuh to every logon event on every domain-joined machine, not just this one. That is a fragile single point of failure for an entire detection layer.

No account lockout was observed or configured for `bftest` — four consecutive failures produced no lockout, throttling, or alerting response beyond the passive logging already discussed. On a real network this account would still be guessable indefinitely.

| Priority | Category | Recommendation |
| --- | --- | --- |
| High | Account policy | Enforce an account lockout policy (e.g., lock after 5 failed attempts) via Default Domain Policy or a scoped GPO — currently absent. |
| High | Detection | Add a correlation rule in Wazuh (or a Suricata threshold rule) for *N failed RDP/NTLM logons from one source within a short window*, so detection doesn't depend on manually noticing a sequence of informational alerts. |
| Medium | Logging | Enable logging on the pfSense rule that permits this traffic (see PTest-E002), so it is independently visible at the firewall layer too. |
| Medium | Tooling accuracy | Correct or suppress Wazuh's default MITRE mapping for rule 60122 (currently T1531, which is wrong for this event type). |
| Low | Process | Periodically audit Default Domain Policy's Advanced Audit Policy Configuration against a known-good baseline, to catch this class of silent gap before it matters during a real incident. |

## Timeline (UTC)

| Time (UTC) | Phase | Event |
| --- | --- | --- |
| 2026-10-15, \~05:08:40–05:08:49 | Detection (network only) | Suricata raises 10 alerts (SID 2001330) correlating to all 5 sessions from PTest-E002's first run, on `enp7s0`. |
| 2026-10-15 | Gap found | Event Viewer and Wazuh show no 4625/4624 events for the attack window. |
| 2026-10-15–10-20 | Investigation | `auditpol`, `secpol.msc`, and `gpresult /r` trace the gap to Local Group Policy being denied in favor of Default Domain Policy. |
| 2026-10-20 | Root cause found | GPMC (as `mwebb-adm`) shows Default Domain Policy's `Audit Logon` subcategory set to Not Configured. |
| 2026-10-20 | Fix applied | `Audit Logon` set to Success and Failure in Default Domain Policy. |
| 2026-10-20, 20:06:53.795–20:07:02.450 | Detection (host, now working) | 4 × event 4625, then 1 × event 4624, matching PTest-E002's second run within about a second. |

## NIST CSF 2.0 view

| Function | Application in this test |
| --- | --- |
| Identify | Assets: Win11Lab, DC01 (domain policy), the Wazuh server, and the sensor. The gap affected every domain-joined machine, not just the one tested. |
| Protect | A local test account scoped to RDP access only. No account lockout policy was in place — a gap identified here. |
| Detect | The LAN port is mirrored to the sensor; Suricata applies Emerging Threats signatures, and the Wazuh agent forwards both `eve.json` and Windows Security-channel events — though the latter depended on a Group Policy setting that was initially missing. |
| Respond | The investigation and fix themselves are the response action: tracing the gap to its root cause in Default Domain Policy and correcting it at the correct level. |
| Recover | Not applicable beyond the fix itself — the gap was closed, and a confirmation pass verified detection was restored. |

## Framework mapping

| Framework | Reference | Relevance |
| --- | --- | --- |
| MITRE ATT&CK | T1110.001 Password Guessing (sub-technique of T1110 Brute Force) | The technique detected; confirmed by sub status 0xC000006A on each failure. |
| NIST CSF 2.0 | PR.AC-07, DE.CM-01, DE.AE-02 | Authentication is monitored; networks and events are analyzed for potentially adverse activity. |
| CIS Controls v8.1 | 4.2 Establish a Secure Configuration Process (audit policy baseline); 6.2 Establish an Access Granting Process; 8.2 Collect Audit Logs; 13.3 Deploy a Network Intrusion Detection Solution | Audit configuration management, account access control, log collection, and network-based detection. |
| NIST SP 800-53 Rev. 5 | AC-7 Unsuccessful Logon Attempts; AU-6 Audit Record Review; AU-12 Audit Record Generation; SI-4 System Monitoring | Lockout policy, log review, the audit-generation gap found and fixed, and ongoing monitoring. |
| ISO/IEC 27001:2022 | A.8.16 Monitoring activities; A.5.17 Authentication information; A.8.15 Logging | Monitoring, credential handling, and the logging gap specifically. |

## Evidence

- [ ] `auditpol /get /subcategory:"Logon"` output showing No Auditing
- [ ] `gpresult /r` showing Local GPO denied, Default Domain Policy applied
- [ ] GPMC: Default Domain Policy settings report, Advanced Audit Configuration
- [ ] GPMC: Audit Policies > Logon/Logoff, before (Not Configured) and after (Success and Failure)
- [ ] Event Viewer / Wazuh search showing no results, pass 1 (the gap)
- [ ] Event Viewer: the 4625 ×4 / 4624 sequence, pass 2, with sub status visible
- [ ] Wazuh dashboard: the same 4625/4624 events, with `rule.id:60122` and its (incorrect) MITRE mapping visible
- [ ] Suricata/Wazuh: the 10 SID 2001330 alerts, `in_iface: enp7s0`

## Spanish summary

Pending: Marvin writes this section in his own words after reviewing the entry.
