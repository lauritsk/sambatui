# Security Audit

## Scope

Whole-repository security review of sambatui.

## Summary

- **Findings**: 1 Medium
- **Risk Level**: Medium
- **Confidence**: High
- **Validation**: `mise run lint` passed, including `uv audit` with no
  known vulnerabilities.

## Findings

### VULN-001 Credentials exposed in process arguments (Medium)

**Location**: `src/sambatui/client.py:88`, executed at
`src/sambatui/app.py:326`

**Confidence**: High

**Issue**: Password auth puts the Samba password into `samba-tool` argv.
UI status text is redacted, but OS process lists or `/proc/<pid>/cmdline`
may still expose argv while `samba-tool` runs.

**Evidence**:

```python
args.extend(["-U", f"{self.config.user}%{self.config.password}"])
```

Then it runs the command:

```python
proc = await asyncio.create_subprocess_exec(*cmd, ...)
```

**Impact**: A local user or process on the same host can potentially steal
Samba/AD credentials and use them with that account's privileges.

**Fix**: Avoid secrets in argv. Prefer Kerberos. For password mode, use a
non-argv Samba credential mechanism if supported, such as a private `0600`
credential file, PTY prompt automation, or keyring integration. If no safe
mechanism exists, remove or strongly gate password mode as unsafe. Add tests
that assert the password never appears in generated command argv.

## Needs Verification

None.
