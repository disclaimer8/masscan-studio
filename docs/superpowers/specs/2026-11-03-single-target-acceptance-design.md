# One explicitly authorized physical target: acceptance design

This is a follow-on to the independently accepted local fixture, not a release
of unrestricted network scanning. The operator authorized continuing autonomously
and choosing a safe test while on hotel Wi-Fi. No hotel device or gateway is a
scan target. Design choices below are the implementer's decisions.

## Intended result

Run the existing rmasscan engine through the packaged GUI and authenticated
macOS helper, send at most four TCP SYN probes to one explicitly authorized
remote IPv4 address at one packet per second, and independently verify the
actual physical-interface capture and saved results. Show truthful completion,
including no-response outcomes; do not infer a port state from silence.

No new backend engine, simulated network pass, broad subnet selection, privilege
prompt loop, persistent network reconfiguration, service enumeration or automatic
scan retry is part of this step. Existing fixture acceptance and its mandatory
checks remain a separate mode. Windows/Linux physical scanning stays disabled.

## Target evidence

The live homepage at [Scanme](http://scanme.nmap.org/) explicitly permits Nmap and
other port scanners, asks for only a few scans per day, and excludes abusive use.
The older [Nmap book examples](https://nmap.org/book/man-examples.html) describe
Nmap-only permission. Preserve the current homepage and retrieval/hash evidence;
this design relies on its more specific present service statement, not a generic
assumption that public hosts may be scanned. The first run is limited to one
attempt and four probes. Recheck the service permission and DNS immediately
before creating a permit. No scan was performed while drafting this design.

If current permission cannot be verified, do not substitute another host. The
policy can still be built and tested offline while the physical run waits for
an explicitly permitted target. An operator-supplied owned target can be a later
separate admission; this first candidate accepts only public unicast IPv4.

## Permit and trust boundary

Use a root-owned, short-lived immutable permit created through a separately
reviewed typed extension of the work-session host. The retained `ae8b` host only
understands fixed fixture operations and the old fixture journal. Stage can
select reviewed executables, but cannot add authority or protocol operations to
that immutable host. An explicit host upgrade/replacement is a prerequisite for
native permit creation. Its typed operations should be CreatePermit, Inspect and
Revoke, with a separate namespace/journal. Never overload Fixture::Up/up-owned,
forge fixture state, or introduce an arbitrary root shell to avoid that upgrade.
Offline policy/storage development does not require replacing the retained host. It fixes a canonical single IPv4 target,
one to four explicit sorted unique TCP ports, rate exactly 1, seed, owner UID,
creation/expiry (at most 15 minutes), a random generation, and the exact executable
hashes. Bind the actual interface index/name/source IPv4/MAC and the complete
single-destination route map observed by root. No hostname, range, CIDR, exclusions,
port zero, implicit expansion, arbitrary interface override or shell command is
accepted as a permit input. Inputs and JSON have bounded size and unknown fields
are refused. A capability is not proof of the remote owner's permission; that
source evidence remains a required operational record.

Read permit files with the existing root trust rules: no symlinks, no extended
ACL, expected owner/mode, bounded reads, stable file identity. Never accept an
environment-variable override or a GUI-created permit. A missing, expired,
changed or malformed permit fails closed. The helper pins the immutable permit
and observed route identity for its session; route/interface/source drift
interrupts execution. Do not alter routes, ARP tables, VPN state or firewall.

Consume a separate root-owned one-use claim before the first possible ARP or TCP
I/O. It survives helper/application exits and prevents retry through another
helper. Losing/cancelling an attempt consumes it; creating another permit is a
new deliberate maintenance action. Read-only settings/route checks do not consume
the claim. A separate claim record keeps the permit itself immutable. Expiry and
identity are rechecked before adapter access and by the existing bounded network
guard. Pin the remaining lifetime to a monotonic deadline at first admission;
wall-clock rollback or replacement invalidates the helper session. The grant has no automatic renewal or unattended retry.

## Integration sequence

1. Implement pure typed permit validation and exact job/route/report/binding
   constraints, with rejection tests. This module alone changes no runtime gate.
2. Add trusted root storage and one-use claiming, with filesystem/adversarial tests.
   Add only typed bounded maintenance operations; no generic root command runner.
   Version/negotiate host support and refuse old hosts before mutations. Prepare
   the upgrade and verify it before requesting any necessary OS authorization;
   keep the existing host available until a replacement is actually ready.
3. Add a distinct candidate environment alongside the unchanged sealed fixture
   environment. Select/pin it from the exact job and trusted permit; never fall
   back to it after a fixture check fails. Unprepared adapter opening is refused.
   Confirm permit consumption precedes every packet-producing path.
4. Preserve the authenticated durable-report acknowledgment and network guard.
   Extend application-side report admission only for this exact constrained job
   shape; it does not create permission or replace root enforcement.
5. Provide a bounded root capture path for the permitted target, verifying
   source/interface, permitted destination and ports, probe order/count/cookies,
   correlated responses, terminal/quiet windows and child cleanup. Expected open
   ports must not be fabricated from website documentation or assumed availability.
6. Complete review, tests, clean release package and CI. Stage exact reviewed
   binaries through the retained host and perform the explicitly reviewed host
   upgrade before any new permit operation. Create one fresh permit only after live
   permission/DNS/route checks and launch one independently captured GUI attempt.
   Preserve evidence and remove the owned permit/capture resources afterward.

Keep the branch draft and undistributed. A physical PASS is specific to one Mac,
one network condition, one remote target and one package; it does not establish
sleep/wake, VPN, direct LAN, arbitrary targets, same-window lifecycle or release
signing/notarization acceptance. Native file-picker/manual UI acceptance remains
separate from the already verified saved-history projection and writer.
