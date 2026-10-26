# Guest helper of rmasscan-lab windows-suite: prints the guest UTC clock as Unix seconds with
# millisecond resolution (one line). The suite compares it with the home-pc clock before any
# raw run, because record-guest refuses a Verify report that is more than 5 s in the future or
# more than 60 s old. pwsh 7.
$ErrorActionPreference = 'Stop'
[string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0:F3}', [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0)
