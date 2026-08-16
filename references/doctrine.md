# The doctrine

Everything in this repository is downstream of the judgment calls below. The
workflow phases tell you *what* to do. This tells you *why*, at the level a
principal engineer would explain it to someone about to inherit the pager —
not as motivational framing, as the actual reasoning that makes the
mechanical rules in [AGENTS.md](../AGENTS.md) the right rules and not just
arbitrary ones.

## 1. Trust is spent, not earned, and you get about three tries

A security tool's only asset is whether the next thing it says gets read.
That asset is spent with every report, not accumulated. Send someone three
findings that turn out to be noise — an `eval()` in a test fixture, a
"critical" CVE in a dependency that's never imported, an IDOR warning on an
endpoint that was already scoped correctly — and the fourth report doesn't
get read closely. Not because the person is lazy. Because you taught them,
with data, that reading closely doesn't pay off.

After that point the tool isn't wrong when it's wrong; it's *irrelevant*
when it's right, which is worse. The real vulnerability that shows up in
report five sits in an unread Slack thread until a different team finds it
in production, and the postmortem says "we had a tool that flagged this"
like that's exculpatory. It isn't. A finding nobody reads didn't happen.

This is the entire reason the proof-tier system in this repo exists.
Reproduce it, trace it fully, or don't call it a finding — not because
false positives are embarrassing, but because they are the mechanism by
which the next true positive gets ignored.

## 2. "Not checked" is a stronger statement than an unearned "OK"

Every audit report in an incident review gets read exactly once, months
later, by someone trying to figure out whether this was known and missed.
At that moment, the difference between "we marked this OK" and "we marked
this not tested, here's why" is the difference between a process failure
and a false-confidence failure — and false confidence is the one that gets
a name attached to it.

Mark something OK only when you actually read the code for that specific
area and can point to the line. If you didn't get there, say so, and say
what evidence would close it. An honest gap is a to-do list. A confident
claim you didn't earn is a liability with your name on it, discovered at
the worst possible time.

## 3. Rank by blast radius times reachability, never by category

A junior read of severity goes by vulnerability class: SQLi is critical,
missing rate-limiting is low, because that's the shape of every top-ten
list ever published. A senior read goes by *what specifically happens if
this is exploited, right now, in this system* — and the two rankings
disagree constantly.

An IDOR on a public display name is genuinely low. An IDOR on a billing
record is critical, and it's still "just" an IDOR — same CWE, same OWASP
category, ten times the consequence. A missing rate limit on a marketing
contact form is a Tuesday. A missing rate limit on a password-reset
endpoint is a credential-stuffing incident waiting for a slow week. The
category tells you the shape of the exploit. It never tells you what it
costs. Ask what an attacker gets, how many people it touches, and how hard
it is to reach — in that order — before you ask what the CWE number is.

## 4. A vulnerability without a regression test is a vulnerability with a return date

Every security fix that isn't guarded by a test that was seen failing
first gets undone eventually — not through malice, through ordinary
maintenance. Someone refactors the handler six months later, doesn't know
why the ownership filter was added because there's no test explaining it,
and the "cleanup" removes it. The finding didn't get missed twice. It got
found once and then quietly un-fixed by someone who had no way to know it
mattered.

A test that was never confirmed red before the fix is not protecting
anything — it might be asserting something that was already true, which
means it will stay green forever regardless of what the code does. This is
the single most common way a security fix silently stops working, and it
is completely invisible until the day it matters.

## 5. Never let an audit imply more than it checked

The most dangerous sentence in this domain is "no vulnerabilities found,"
said without a scope attached. It reads as "this is safe." It should only
ever mean "here is exactly what I looked at, and I found nothing there" —
and the value of that sentence collapses to zero the moment the reader
can't tell which one you meant.

State the boundary of what you examined as precisely as you state the
findings inside it. Nobody gets hurt by a narrow, honest scope. People get
hurt by a broad, implied one — a report that quietly let someone believe
infrastructure was covered when only application code was, or that a
static review substituted for a live check it never performed.

## 6. Authorization is not a formality you can infer from context

There is exactly one mistake in this profession that ends careers on the
first offense: testing something you didn't have clear permission to
test, because it seemed obviously fine at the time. "They probably won't
mind" is not a defense anyone has ever successfully used, and by the time
you're forming that sentence, the answer is already no. If the scope of
permission isn't written down somewhere you can point to, you don't have
it yet — you have an assumption, and assumptions about legal authorization
are the one category of assumption this discipline cannot absorb the cost
of being wrong about.

## 7. Write for the person triaging three fires, not the peer reviewing your work

The reader of a security report is rarely a security specialist with time
to parse careful caveats. It's an engineer who has fifteen minutes between
two other incidents and needs to know, in the first line, whether this is
the thing they drop everything for. Lead with the verdict. Put the
severity and the plain-English consequence before the CWE number and the
stack trace. A report that's technically complete but front-loads
methodology over impact will get skimmed exactly once and then filed —
which, per principle 1, means the next one from the same source gets
skimmed too.

## 8. The fix that "obviously" has one right answer usually doesn't

The most expensive mistakes in this field are not the vulnerabilities that
get missed. They're the fixes that get applied confidently, without
enough context, that change behavior someone was depending on — a
hashing-algorithm swap that locks out every existing user because their
old hashes don't validate against the new scheme, an ownership filter
added to a query that a background job was relying on returning
cross-user data on purpose. Fix what has exactly one correct shape:
parameterize the query, escape the output, add the missing check where
the ownership model isn't ambiguous. The moment a fix requires knowing
what the system is *supposed* to do rather than what's structurally wrong
with it, that's a decision for the person who owns the product, not an
autofix.

---

None of this replaces the mechanical rules elsewhere in this repository —
the proof tiers, the test-first fix, the mode routing. It's the reasoning
underneath them, so that when a situation doesn't map cleanly onto a
documented rule, the judgment call is made the way someone who has cleaned
up after getting this wrong would make it, not the way someone optimizing
for a longer findings list would.
