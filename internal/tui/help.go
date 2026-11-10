package tui

const help = `sambatui — native Go client

Ctrl+O  Connection setup and private preferences
Ctrl+P  Command palette (also discovery and smart-view thresholds)
z       Enumerate DNS zones
l       LDAP search (base, kind, text, row limit)
q       Query DNS management records by name/type
1–3     DNS duplicate/CNAME, A/PTR, PTR/A checks
4–7     Inactive users, cleanup candidates, stale computers, groups
8       Full health checks; failed/limited checks are explicit notices

Tab     Switch sidebar/results focus
j/k     Move; arrows also work
PgUp/Dn Page movement; Ctrl+U/D half page
g/G     First/last; Home/End also work
Enter   Open sidebar item or row details; j/k scroll details
/       Local literal filter
s       Cycle sort field/direction
Space   Toggle selection; v sets range anchor then selects range
Esc     Clear selections/filter or dismiss form/details
m       Load more LDAP/smart rows (+200, maximum 5000)
r       Refresh current view

 a      Guided add (DNS type-specific fields or LDAP entry)
 u/e    Edit one selected record/entry
 d      Delete selected records/entries
 f      Guided fix for one finding (PTR add / account disable)

Forms: Tab/Enter next field, Ctrl+U clear, Backspace erase,
Ctrl+S preview/submit, Esc cancel. Password whitespace is preserved.
All writes require typing yes after reviewing the original target.
A form reservation prevents overlapping keyboard/palette/guided flows.

Ctrl+C  Request cancellation during writes; waits for worker cleanup.
        Cancellation is NOT rollback. A lost response is NOT failure
        to commit. Unknown outcomes block subsequent writes.
R       Inspect uncertain write on original DC, then explicit manual
        reconciliation. If the original operation might still be
        pending, DO NOT acknowledge; investigate that DC first.

LDAP conditional edits/deletes/disables require advertised RFC 4528
support AND a critical revision assertion. No unsafe fallback. Samba
4.22 does not advertise this control; these writes are refused there.
Reads/adds and DNS operations remain available.

p       Load private password file (first line minus CR/LF)
P       Save password privately after confirmation (not encrypted)
Q       Quit only when no write flow is pending

No telemetry, Python, Docker, samba-tool, klist, or native GSSAPI is
used by the client. The existing remote DC is the server, not a client
runtime dependency. Never point disposable integration tests at it.`
