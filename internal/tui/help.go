package tui

const help = `Ctrl+O  Connection (individual DC, verified TLS)
Ctrl+P  Commands and AD service discovery
z       DNS zones
l       LDAP search
q       DNS query

Tab     Switch panes (Shift+Tab also works)
↑/↓     Move (j/k also work in the browser)
PgUp/Dn Page; Ctrl+U/D half page
g/G     First/last (Home/End also work)
Enter   Open a sidebar item or row details
/       Local, case-insensitive literal filter
s       Change sort column/direction
Space   Toggle batch selection (*)
·       Active navigation choice (independent of keyboard focus)
v       Set a range start, then select through the current row
Esc     Clear selection/filter or close a dialog
m       Load 200 more LDAP rows (maximum 5000)
r       Refresh; clears selection
!       Last error

a       Add
u/e     Edit one record/entry
d       Delete selected records/entries

Forms: Tab next, Shift+Tab previous, Ctrl+U clear,
Backspace erase, Ctrl+S submit, Esc cancel.
Enter runs the selected command or applies a filter.
Other forms: ↑/↓ or Tab to move, ←/→ to choose an option.
Text fields: ←/→, Home/End and Delete edit at the caret.
Passwords preserve whitespace. Writes require typing yes.

Ctrl+C  Cancel a running write and wait for cleanup.
        Cancellation is not rollback.
R       Inspect an unknown outcome on the original DC.
        Reconcile only after verifying the outcome and that
        the remote operation has stopped.

p       Load the private password file
P       Save the password unencrypted (0600)
Ctrl+Z  Suspend/resume (not during a write)
Q       Quit (not during a write)`
