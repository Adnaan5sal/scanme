# Compliance checklist §16–28

---

## §16 CORS [code]

Policy explicitly defined (not framework defaults). No wildcard origin for
authenticated endpoints. Allowed origins enumerated and match intended list
(no `localhost`/`*` leaking to production). `credentials: true` combined
with specific origins only. Dev origins not in production config.

---

## §17 Dependency & Supply-Chain Security [code] / [confirm]

[code] — lockfiles present and committed; run `npm audit`/`pip-audit`/`cargo
audit`; check reachability before ranking severity (a critical in a
build-time-only dev dependency is less urgent than one in the request path).

[confirm] — is scanning automated in CI? Process for new disclosures?
Container images scanned?

---

## §18 Infrastructure Security [confirm]

All [confirm] — cannot be verified from application source: production
isolated from dev; firewall rules; admin access restricted (no public SSH);
OS/containers patched; cloud IAM least privilege; databases on private
networks; internal services not exposed unnecessarily. NOT TESTED unless the
user can confirm with evidence.

---

## §19 CDN / WAF / DDoS Protection [confirm]

CDN configured, origin IP protected; WAF rules configured and reviewed;
DDoS protection enabled; bot protection where appropriate; DNS secured.

---

## §20 Logging & Audit Trails [code] / [confirm]

[code] — auth events logged (success/failure/logout); authorization
failures logged; privileged/admin actions logged; timestamps present; logs
don't contain passwords/tokens/session identifiers; logs don't unnecessarily
contain sensitive personal data.

[confirm] — controlled access to logs? Retention period? Protected from
modification?

---

## §21 Monitoring & Alerting [confirm]

Application/infrastructure/database monitoring enabled; error monitoring
(Sentry, Datadog); authentication anomalies monitored; rate-limit violations
alert; backup failure alerts exist; on-call procedure defined.

---

## §22 Error Handling [code]

Production errors don't expose stack traces; database errors not exposed;
internal file paths not exposed; credentials/tokens not in error responses;
generic user-facing messages, detail to internal logs only.

---

## §23 Backup & Disaster Recovery [confirm]

Automated backups enabled; encrypted; access restricted; stored separately
from production; multiple generations retained. **Backup restoration has
been successfully tested** — ask specifically: "When was the last time you
successfully restored from a backup, and did the application work correctly
after?" A backup that has never been tested is a hypothesis, not a control.
RPO/RTO defined; DR procedures documented and tested.

---

## §24 Availability & Reliability [code] / [confirm]

[code] — health check endpoint exists; request timeouts configured;
external service call timeouts configured; DB connection pooling
configured; background job queue for long-running work.

[confirm] — retry logic with backoff to prevent retry storms? Circuit
breakers for external dependencies? Scaling and failover strategy?

---

## §25 CI/CD Security [code] / [confirm]

[code] — no secrets in plaintext in pipeline config files; secrets
referenced from environment.

[confirm] — production branches protected (PR + review)? Automated tests
before deployment? SAST/dependency/secret scanning in CI? Rollback
procedure?

---

## §26 Security Testing [confirm] / [code]

[code] — is there a `tests/security/` directory? Do existing tests cover
auth/authz/input validation?

[confirm] — which are performed: auth/authz testing, input
validation/injection testing, XSS/CSRF/file-upload testing, rate-limit
testing, dependency scanning (SAST), DAST/penetration testing?

If a standing test suite is wanted, see [test-patterns.md](test-patterns.md)
— it generates exactly the coverage this section asks about.

---

## §27 Vulnerability Management [confirm]

Discovery process exists; vulnerabilities categorized by severity; critical
and high have defined remediation timelines; exceptions require documented
approval with owner and expiry date.

---

## §28 Incident Response [confirm]

Incident-response plan exists with defined severity levels; security
contacts identified; specific procedures for credential compromise, data
breach, system isolation, evidence preservation, communication, recovery;
post-incident reviews performed; corrective actions tracked; exercises
performed periodically.

If none of these exist: FAIL HIGH. An undocumented response to a real
incident under pressure will be slower and more damaging than one with even
a minimal written procedure.
