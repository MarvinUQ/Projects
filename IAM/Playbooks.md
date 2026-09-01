

# IAM-PB-001: Residual Access After AD Object Relocation or Recycle Bin Restoration
 
**Environment:** HLSLC (HomeLab Simulated Logistic Company) — lab.local, DC01 (Windows Server 2025 Core)
**Related portfolio entries:** `[IAM]-E001`, `[ITO]-E001`
**Severity (lab-rated):** Medium — no external exposure, but models a real privilege-creep pattern
**MITRE ATT&CK:** T1098 (Account Manipulation) → enables T1078 (Valid Accounts)
**Analyst tagging caveat:** Wazuh auto-tags group-membership-change events as T1484 (Domain Policy Modification). That mapping is loose — T1484 is about GPO/trust manipulation, not group membership. Treat SIEM auto-tags as a starting point, not ground truth; verify against the ATT&CK technique definition before it goes in a report.
**Last validated:** Against HLSLC test accounts rcallahan, lmarquez, ffaker, abrooks (Aug 2026)
 
---
 
## 1. Purpose & Scope
 
This playbook governs response when an AD object's **group membership no longer matches its current organizational placement** — the specific failure mode confirmed twice in HLSLC:
 
- **Scenario A — OU move:** Moving a user object between OUs does **not** remove group memberships tied to the old OU/role. Confirmed on `lmarquez`: moved Accounting → Warehouse, retained Accounting group membership until manually cleaned up.
- **Scenario B — Recycle Bin restore:** Restoring a deleted object via `Restore-ADObject` silently reinstates **all prior group memberships**, including ones that may have been revoked *before* deletion. Confirmed on `ffaker`: delete → restore returned full Helpdesk group membership automatically.
Both are the same underlying risk — stale entitlement surviving a lifecycle event — reached by different paths. Out of scope: initial account provisioning errors (that's a standard access-request playbook, not this one).
 
---
 
## 2. Detection Criteria — and the Gap You Have to Design Around
 
This is the part that makes this playbook non-generic: **your own testing showed the "obvious" event IDs don't fire.**
 
| Event | What it should mean | Fires in HLSLC? |
|---|---|---|
| 5139 (DS object moved) | OU move happened | **No** — confirmed via Event Viewer, zero events at OS source, not a Wazuh ingestion gap |
| 5138 (DS object undeleted) | Recycle Bin restore happened | **No** — same finding |
| 5141 (DS object deleted) | Object deleted | **No** |
| 5136 (DS object modified) | Attribute change (incl. `member`) | **Yes** — reliable |
| 5137 (DS object created) | New object | **Yes** — reliable |
| 4728 / 4729 (member added/removed — global group) | Group membership delta | **Yes** — reliable |
| 4738 | Descriptive attribute change (Title/Department) | **No** for attribute-only edits — only 5136 catches these |
 
**Practical consequence:** you cannot detect "a move happened" or "a restore happened" directly. You can only detect *the group-membership side effect* — 4728/4729 or a 5136 with `member` in the changed-attribute list. The playbook trigger has to be built on that indirect signal, not the intuitive one.
 
**Primary trigger (use this):**
> Wazuh alert on 4728/4729 or 5136 (attribute=`member`) where the target object's `memberOf` set includes a group **not consistent with the object's current OU-to-group mapping**.
 
**Recommended compensating control (not yet implemented in HLSLC — flag as follow-up):** enable PowerShell Module Logging / Script Block Logging (Event ID 4104) on DC01. `Move-ADObject` and `Restore-ADObject` are cmdlet invocations, so 4104 would catch the *operator action* even though DS auditing doesn't catch the *object-level result*. This is the standard playbook move when native audit logging has a proven blind spot: add a secondary source at a different layer instead of re-tuning the same SACL you already confirmed is configured correctly.
 
---
 
## 3. Roles
 
| Role | Responsibility |
|---|---|
| Tier 1 (triage) | Confirm alert, pull current `MemberOf`, escalate if mismatch confirmed |
| Tier 2 / IAM admin | Reconcile membership, document root cause, close ticket |
| GRC (post-incident) | Confirm finding maps correctly to control framework (see §6) |
 
---
 
## 4. Investigation Steps
 
1. Identify the object: `Get-ADUser -Identity <sam> -Properties MemberOf,Department,DistinguishedName`
2. Compare current OU (`DistinguishedName`) against current `MemberOf` — build the expected group set from the OU-to-group mapping table for HLSLC.
3. Pull DS Changes history for the object: filter Wazuh/Event Viewer for 5136 where `ObjectDN` matches, review `AttributeLDAPDisplayName = member` entries and timestamps.
4. Pull Account Management history: 4728/4729 events for the same object, cross-reference actor (`SubjectUserName`) — in HLSLC testing this was consistently `mwebb-adm`, confirm it matches an authorized admin action, not an anomaly.
5. If restore is suspected and 4104 logging is enabled: search for `Restore-ADObject` invocation in the relevant time window.
6. Establish the drift window: time between the move/restore and the membership correction (if any). In the `lmarquez` case this was directly measurable via the 5136 timestamps (12:49:51 → 13:58:31).
---
 
## 5. Containment
 
1. Do **not** wait for a full root-cause writeup — remove the stale group membership immediately if it grants access inconsistent with current role:
   `Remove-ADGroupMember -Identity <group> -Members <sam> -Confirm:$false`
2. If the restore itself was unauthorized (not a legitimate recovery), consider disabling the account pending review rather than just stripping groups.
---
 
## 6. Eradication & Recovery
 
1. Reconcile membership to match the OU-to-group mapping exactly — add any group the current role requires that's missing, remove anything stale.
2. Verify: `Get-ADUser -Identity <sam> -Properties MemberOf` shows only expected groups.
3. Document the correction with before/after `MemberOf` output as evidence — this is what closed the `lmarquez` case in HLSLC.
4. GRC cross-reference: this control gap maps to **NIST SP 800-53 AC-2 (Account Management)** — specifically the requirement that account attributes be reviewed for consistency after account modification events, not just at creation. Under **NIST CSF 2.0** it lands in PR.AA (Identity Management, Authentication and Access Control).
---
 
## 7. Post-Incident / Preventive Recommendations
 
1. **No automated reconciliation exists in AD by default** — group membership is never auto-derived from OU placement. If HLSLC wants to close this permanently rather than catch it reactively, the real fix is a scheduled reconciliation script (compare OU → expected group, alert or auto-correct on drift), not better logging.
2. Enable 4104 PowerShell logging on DC01 to cover the Scenario B detection gap (see §2).
3. Add a periodic (e.g., weekly) access review specifically for any account that has passed through Recycle Bin restore — native logging won't flag these later, so they need a manual or scripted check outside the SIEM.
4. Treat the 5139/5138/5141 non-firing behavior as a **documented, closed finding** (already done in `[ITO]-E001`) — don't re-open investigation into "why," route future work into the compensating controls above instead.
---
 
## 8. Evidence Trail (HLSLC test accounts)
 
- `rcallahan` — correct-placement baseline, confirms normal-path logging works
- `lmarquez` — Scenario A (OU move), 5136 timestamps confirm drift window and manual correction
- `ffaker` — Scenario B (delete → Recycle Bin restore), confirms automatic group reinstatement
- `abrooks` — confirms 4738 does not fire for descriptive-attribute-only edits (Title/Department), only 5136 does
