# Compliance checklist §29–35

---

## §29 Privacy & Data Protection [confirm] / [specialist]

[code] — personal data not logged unnecessarily; data minimization in API
responses.

[confirm] — personal data inventory exists? Retention periods
defined/enforced? Data-deletion procedures exist and tested? Privacy notice
exists? Consent mechanisms where required? Applicable privacy laws
identified (GDPR, India DPDP, CCPA, HIPAA)?

[specialist] — do not assess whether a privacy notice meets regulatory
requirements, consent legal sufficiency, or cross-border transfer
compliance. Requires qualified counsel.

---

## §30 Third-Party & Vendor Security [confirm]

Third-party services inventoried; API permissions minimized (OAuth scopes,
IAM roles); credentials securely stored; data-processing terms reviewed;
breach procedures understood; critical vendor dependencies have contingency
plans.

---

## §31 Payment Security [code] / [confirm] / [specialist]

**Only applicable when the app handles payments or card data.** Otherwise
N/A.

[code] — card data not stored unnecessarily (PCI DSS prohibits storing
CVV); payment APIs authenticated; webhook signatures verified (not just raw
payload); payment status validated server-side; duplicate transactions
prevented (idempotency keys); refund operations protected; payment events
logged.

[specialist] — PCI DSS compliance certification requires a Qualified
Security Assessor or SAQ. This checklist identifies code-level gaps only.

---

## §32 AI / LLM Security [code] / [confirm]

**Only applicable to AI-powered applications.** Otherwise N/A. See
[ai-threats.md](ai-threats.md) for the full threat model — this section is
the compliance-checklist summary of it.

[code] — user input separated from system instructions in prompt
construction; tool calls require authorization before execution; tool
parameters validated; token/request limits at the provider level; rate
limiting on AI endpoints.

[confirm] — has indirect prompt injection been tested (cannot be proven
safe, only structurally mitigated)? RAG authorization filters at query time?
Agents operate with minimum privileges? AI logs reviewed for sensitive data
exposure? AI spending controls exist?

---

## §33 Administrative Security [code] / [confirm]

[code] — admin routes protected with role checks; administrative actions
logged; sensitive admin operations require re-authentication.

[confirm] — admin accounts individually assigned (no shared credentials)?
MFA enforced for all admins? Admin sessions have timeouts? Access reviewed
periodically? Controlled, audited break-glass procedure?

---

## §34 Compliance Documentation & Evidence [confirm] / [specialist]

[confirm] — control registry with owners and evidence exists? Evidence
collected per control (screenshots, config exports, logs)? Exceptions
formally approved with owner and deadline? Auditor and sign-off date for
last review?

The `SECURITY_AUDIT.md` this skill produces (via `findings.py report`)
serves as the §34 evidence artifact — Control IDs, evidence quoted, owners
assigned, remediation deadlines set, all pulled from the finding store.

Formal certifications (SOC 2, ISO 27001, PCI DSS) are [specialist] — the
certification body requires evidence in their specific format, assessed by
their auditors. This produces internal working documentation that prepares
for those assessments but does not substitute for them.

---

## §35 Final Production Security Gate

**The go / no-go checklist before releasing to production.**

Each item must be CLEAR, BLOCKED, or RISK-ACCEPTED (with documented risk
owner and acceptance date). Any BLOCKED item without RISK-ACCEPTED status
should prevent production deployment.

| Gate item | Mapped to |
|-----------|-----------|
| No known critical vulnerabilities | §27, finding store |
| No unresolved high-risk vulns without formal risk acceptance | §27 |
| Authentication tested | §3, §26 |
| Authorization tested | §4, §26 |
| API security tested | §10, §26 |
| Database security reviewed | §11 |
| Secrets scanned | §12 |
| Dependencies scanned | §17 |
| Security headers verified | §15 |
| CORS verified | §16 |
| File uploads tested | §13 |
| Logging verified | §20 |
| Monitoring verified | §21 |
| Backups verified | §23 |
| Restore procedure tested | §23 |
| Incident-response procedure available | §28 |
| Production configuration reviewed | §2, §18 |
| Security testing completed | §26 |
| Compliance requirements reviewed | §34 |
| Outstanding risks formally documented | §27 |
| Final security approval recorded | §34 |

**Overall gate decision:**
- **PASS** — all items CLEAR or RISK-ACCEPTED with documentation
- **CONDITIONAL** — high-risk items RISK-ACCEPTED with owner + date; all
  criticals CLEAR
- **FAIL** — any critical item BLOCKED, or any high-risk item BLOCKED
  without risk acceptance

---

## Standards / framework mapping

| Framework | Primary purpose |
|-----------|----------------|
| OWASP ASVS | Detailed web application security requirements |
| OWASP Top 10 | Major categories of web application risk |
| OWASP WSTG | Web application security testing |
| OWASP API Security Top 10 | API-specific security risks |
| ISO/IEC 27001 | Information security management system |
| NIST CSF | Cybersecurity risk management |
| CIS Controls | Prioritized cybersecurity controls |
| SOC 2 | Controls for service organizations |
| PCI DSS | Payment-card security |
| GDPR | EU personal-data protection |
| India DPDP | Indian digital personal-data protection |

Rough section-to-framework mapping: §3–9 → OWASP ASVS ch. 2–5 / Top 10
A01–A07 · §10 → OWASP API Security Top 10 · §1, §27–28 → ISO 27001 Annex A /
NIST CSF Govern+Respond · §23–24 → ISO 27001 A.17 / NIST CSF Recover · §31 →
PCI DSS req. 3, 4, 6 · §29 → GDPR Art. 5, 13, 17, 25, 32.
