# Studio: authenticated Windows session transport

Continue spec §5.3 independently of rmasscan. Replace inherited stdio for Windows
simulation with the named-pipe path that a future elevated launcher can use.
No UAC/installation, raw gate changes, driver installation or live lab work.

## Contract and implementation

1. Windows-only platform module: random local pipe name, one instance,
   FIRST_PIPE_INSTANCE, REJECT_REMOTE_CLIENTS, protected DACL for current user SID.
   Both ends authenticate peer PID against an open retained process handle and
   compare process creation time, executable, SID and logon session identity.
   Owner identity in argv is public; no session secret is passed there.
2. Overlapped pipe I/O with owned handles; pending requests are cancelled and
   completed before buffers/OVERLAPPED are released. Connect has a deadline and
   cancellation. Close wakes pending reads/writes; peer death terminates waits.
   Client SQOS restricts server impersonation to identification.
3. Runner --connect-pipe authenticates UI before Hello and monitors its held
   process handle. Windows controller launches the ordinary child, pins its
   identity, connects over pipe and closes/reaps it on every failure/drop path.
   Existing version/session/attempt/sequence checks remain unchanged.
4. Tests on Windows: roundtrip, wrong/stale process identity, endpoint format,
   explicit DACL inspection, connect cancellation/timeout, pending-read shutdown,
   runner handshake and disconnect, simulation lifecycle/volume through the pipe.
   Mac/Linux full regression checks remain required; Windows execution is CI.
5. Fresh security-focused whole-branch review, docs, clean package and green
   three-OS CI before merge. Keep UAC and other-account credentials unclaimed.

## Review focus

Handle ownership, overlapped-buffer lifetime and cancellation races; peer identity
bound to a live retained handle rather than a reused PID; no default/Everyone
DACL; local-only pipe name/remote refusal; failing handshake/launch leaves no
runner; no raw scanning or elevation inferred from transport success.

## API references

- [Named pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [CancelIoEx lifetime contract](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex)
- [Client SQOS](https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client)
