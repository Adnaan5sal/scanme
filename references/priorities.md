# Reference architecture and priorities

Used in Compliance Mode reports to explain *why* a gap matters, and to keep a
long checklist from burying what actually matters under what doesn't.

## A reasonable production architecture

Not every project needs all of this — a solo SaaS on a single VPS is not
failing by not having a load balancer. But this is the shape to grow toward
as stakes and scale increase, and it's useful as a mental model for where a
given project's gaps actually are:

```
                    INTERNET
                       |
                       v
                +--------------+
                |     CDN      |
                +------+-------+
                       |
                  WAF / DDoS
                       |
                       v
                +--------------+
                | Load Balancer|
                +------+-------+
                       |
              +--------+--------+
              v                 v
        +-----------+     +-----------+
        | Frontend  |     |  Backend  |
        +-----------+     +-----+-----+
                                |
                  +-------------+--------------+
                  v             v              v
             PostgreSQL       Redis       Object Storage
                  |             |              |
                  +-------------+--------------+
                                |
                                v
                         Background Queue
                                |
                         +------+------+
                         v             v
                    AI Workers     File Workers
                         |
                         v
                 External AI APIs
```

Wrapped around every layer, not bolted onto one:

```
Authentication - Authorization - Rate Limiting - Secrets Management -
Logging - Monitoring - Backups - CI/CD Security - Vulnerability Scanning -
Audit Logs - Incident Response
```

Use this to explain *why* a gap matters, not just to list it — "you have no
load balancer" is a fact; "your app has a single point of failure between the
CDN and your database, so one server restart takes the whole app down" is the
reason someone acts on it.

## The 10 things to never skip

If a project needs to prioritize (most fast-moving projects do), these are
the floor — everything else matters but these are where a real incident
happens first:

1. HTTPS
2. Proper authentication
3. Server-side authorization
4. Input validation
5. Parameterized database queries
6. Secure secrets management
7. Rate limiting
8. Secure file uploads
9. Backups + **tested** restoration
10. Logging + monitoring

For an AI product specifically, add (see [ai-threats.md](ai-threats.md)):

11. Prompt-injection defenses
12. RAG access-control isolation
13. AI/API spending limits
14. Tool/agent sandboxing
15. Tenant isolation
16. AI data-privacy controls

## The mindset to keep in every report

Security protects the application. Reliability keeps it running.
Observability tells you when either one is failing. A project can have
excellent security and still go down from a database connection leak; it can
have excellent uptime and still leak every user's data through one missing
ownership check. Don't let a strong score in one dimension imply health in
the others — call out which dimension each gap actually belongs to, so the
summary reads as separate signals, not one blended score.
