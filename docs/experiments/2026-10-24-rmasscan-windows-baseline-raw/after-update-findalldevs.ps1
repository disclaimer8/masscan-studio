[Console]::OutputEncoding=[Text.Encoding]::UTF8
"captured_utc=" + (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") + " (after update 26300.9711)"
$id=[Security.Principal.WindowsIdentity]::GetCurrent(); "elevated=" + ([Security.Principal.WindowsPrincipal]$id).IsInRole('Administrators') + " user=" + $id.Name
whoami /groups | Select-String 'High Mandatory|Medium Mandatory'
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class P {
 [DllImport(@"C:\Windows\System32\Npcap\wpcap.dll", CallingConvention=CallingConvention.Cdecl)] public static extern int pcap_findalldevs(out IntPtr d, byte[] err);
 [DllImport(@"C:\Windows\System32\Npcap\wpcap.dll", CallingConvention=CallingConvention.Cdecl)] public static extern void pcap_freealldevs(IntPtr d);
 public static string[] List(out int rc){ IntPtr d; var e=new byte[256]; rc=pcap_findalldevs(out d,e); var l=new System.Collections.Generic.List<string>();
  for(IntPtr p=d;p!=IntPtr.Zero;p=Marshal.ReadIntPtr(p)){ l.Add(Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(p,IntPtr.Size))+" | "+Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(p,2*IntPtr.Size))); }
  if(d!=IntPtr.Zero) pcap_freealldevs(d); return l.ToArray(); }
}
'@
$rc=0; [P]::List([ref]$rc) ; "rc=$rc"
Get-NetAdapter | Format-Table Name,InterfaceDescription,Status -Auto
Get-Command pwsh,git,python | % { "$($_.Name) $($_.Version) $($_.Source)" }
(Get-CimInstance Win32_OperatingSystem).Version
