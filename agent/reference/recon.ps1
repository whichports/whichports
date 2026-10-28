# recon.ps1 - READ ONLY. Collects every filtering layer on one Windows host.
# Changes nothing. Run elevated so socket-to-process mapping works.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File recon.ps1 > recon-$env:COMPUTERNAME.txt
#
# The question it answers: for every port bound on this host, which layers would
# allow or block it, and do they agree?
#
# The Windows counterpart to reference/recon.sh. The model is NOT the same as Linux.
# Four things measured on Windows Server 2025 that a Linux mental model gets wrong:
#
#   1. A socket bound to :: only STILL ANSWERS IPv4. Windows dual-stack sockets accept
#      v4 as mapped addresses. Do not infer "v4 unreachable" from a missing 0.0.0.0 bind.
#   2. http.sys holds ports 80, 443, 445, 5985, 47001, 5357 in the kernel, so the owner
#      reads as System / PID 4 with no image path. The URL reservation table names the
#      real service. This is the Windows analogue of systemd socket activation.
#   3. There are SIX policy stores, not one. ActiveStore is the merge. A collector that
#      reads only PersistentStore misses every GPO rule and all of Windows Service
#      Hardening, which was 178 always-enabled rules on a bare 2025 install.
#   4. Get-NetUDPEndpoint counts ephemeral outbound sockets. On a domain controller it
#      returned 5036 "ports". That is not 5036 services. Never report it as such.

$ErrorActionPreference = 'Continue'
function Section($t){ "`n`n===== $t =====" }   # NB: do not name this 'H', that is an alias for Get-History

Section "HOST"
"host:    $env:COMPUTERNAME"
$cs = Get-CimInstance Win32_ComputerSystem
"domain:  $($cs.Domain)  joined=$($cs.PartOfDomain)  role=$($cs.DomainRole)  (4/5 = domain controller)"
$os = Get-CimInstance Win32_OperatingSystem
"os:      $($os.Caption) build $($os.BuildNumber).$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR)"
"booted:  $($os.LastBootUpTime)"
"date:    $(Get-Date -Format s)"

# ---------------------------------------------------------------- LAYER 0
# What is actually listening, and on which address. :: or 0.0.0.0 means "reachable if
# something upstream permits it". 127.0.0.1 means unreachable whatever the rules say.
# A specific address means reachable only on THAT interface, which is the one case
# where the bind address really does decide.
Section "LAYER 0: listening TCP, with owner"
Get-NetTCPConnection -State Listen | ForEach-Object {
    $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [pscustomobject]@{
        Port = $_.LocalPort; Addr = $_.LocalAddress; PID = $_.OwningProcess
        Proc = $(if ($p) { $p.ProcessName } else { '?' })
        Path = $(if ($p) { $p.Path } else { '' })
    }
} | Sort-Object Port, Addr | Format-Table -Auto

Section "LAYER 0b: who really owns the http.sys ports (System/PID 4 is not the answer)"
netsh http show urlacl

Section "LAYER 0c: service behind each svchost PID"
Get-CimInstance Win32_Service | Where-Object State -eq 'Running' |
    Select-Object ProcessId, Name, DisplayName | Sort-Object ProcessId | Format-Table -Auto

# ---------------------------------------------------------------- PROFILES
# Per ADAPTER since Windows 7 / Server 2008 R2. Vista had one active profile at a time
# and a lot of documentation still describes that older model. A rule scoped to Private
# does nothing on an adapter classified Domain, and the UI still shows it enabled.
Section "WHICH PROFILE EACH ADAPTER IS IN"
Get-NetConnectionProfile | Select-Object InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity | Format-Table -Auto

Section "PROFILE DEFAULTS - effective, not 'NotConfigured'"
# Get-NetFirewallProfile reports DefaultInboundAction=NotConfigured even when the
# firewall is plainly blocking. netsh prints the value actually in force. Read netsh.
netsh advfirewall show allprofiles
"--- cmdlet view, for the contrast ---"
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -Auto

# ---------------------------------------------------------------- STORES
Section "POLICY STORES - ActiveStore is the merge, and the only one that decides"
foreach ($s in 'PersistentStore','ActiveStore','SystemDefaults','StaticServiceStore','ConfigurableServiceStore','RSOP') {
    try {
        $r  = @(Get-NetFirewallRule -PolicyStore $s -All -ErrorAction Stop)
        $en = @($r | Where-Object { $_.Enabled -eq 'True' }).Count
        "{0,-26} total={1,-6} enabled={2}" -f $s, $r.Count, $en
    } catch { "{0,-26} ERROR: {1}" -f $s, $_.Exception.Message }
}
"--- raw registry rule store, should match PersistentStore ---"
$fw = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
"registry values: " + (((Get-ItemProperty $fw).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }).Count)

Section "WHERE EACH ACTIVE RULE CAME FROM"
Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction SilentlyContinue |
    Group-Object PolicyStoreSourceType | Select-Object Count, Name | Format-Table -Auto

Section "ENABLED INBOUND ALLOW RULES, WITH PORT, PROFILE AND SCOPE"
# Batched on purpose. One Get-NetFirewallPortFilter per rule is a CIM round trip each
# and takes minutes on a few hundred rules.
$pf = @{}; Get-NetFirewallPortFilter    -PolicyStore ActiveStore | ForEach-Object { $pf[$_.InstanceID] = $_ }
$af = @{}; Get-NetFirewallAddressFilter -PolicyStore ActiveStore | ForEach-Object { $af[$_.InstanceID] = $_ }
Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Allow -Enabled True |
    ForEach-Object {
        $k = $_.InstanceID
        if ($pf[$k].LocalPort -and $pf[$k].LocalPort -ne 'Any') {
            [pscustomobject]@{
                Proto   = $pf[$k].Protocol
                Port    = (@($pf[$k].LocalPort) -join ',')
                Profile = $_.Profile
                Remote  = (@($af[$k].RemoteAddress) -join ',')
                Rule    = $_.DisplayName
                Source  = $_.PolicyStoreSourceType
            }
        }
    } | Sort-Object Proto, Port | Format-Table -Auto -Wrap

# ---------------------------------------------------------------- OTHER LAYERS
Section "PORTPROXY - forwarding that no firewall rule describes"
netsh interface portproxy show all

Section "IPSEC CONNECTION SECURITY RULES"
@(Get-NetIPsecRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count

Section "ADDRESSES"
Get-NetIPAddress | Where-Object AddressState -eq 'Preferred' |
    Select-Object InterfaceAlias, IPAddress, PrefixLength, AddressFamily, PrefixOrigin |
    Sort-Object InterfaceAlias | Format-Table -Auto

Section "UDP ENDPOINTS - READ THE WARNING AT THE TOP BEFORE REPORTING THIS"
"distinct UDP local ports: " + (Get-NetUDPEndpoint | Select-Object -Expand LocalPort -Unique | Measure-Object).Count
"of which plausibly services (port < 1024 or a known high service port):"
Get-NetUDPEndpoint | Where-Object { $_.LocalPort -lt 1024 -or $_.LocalPort -in 1434,3389,3702,5353,5355,41641 } |
    ForEach-Object {
        $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [pscustomobject]@{ Port=$_.LocalPort; Addr=$_.LocalAddress; Proc=$(if($p){$p.ProcessName}else{'?'}) }
    } | Sort-Object Port, Addr -Unique | Format-Table -Auto

Section "INSTALLED ROLES"
Get-WindowsFeature | Where-Object Installed | Select-Object Name, DisplayName | Format-Table -Auto

Section "END"
