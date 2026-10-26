# Microsoft Defender state, threat history and exclusions. Each part is read on its own so
# that one failure does not hide the others; failed parts are listed in errors.
$o = [ordered]@{
    realtime = $null; tamper = $null; amrunning = $null; sigage = $null
    threats = $null; excl_paths = $null; excl_ext = $null; excl_proc = $null; excl_ip = $null
    errors = @()
}
try {
    $s = Get-MpComputerStatus
    $o.realtime = [bool]$s.RealTimeProtectionEnabled
    $o.tamper = [bool]$s.IsTamperProtected
    $o.amrunning = [string]$s.AMRunningMode
    $o.sigage = [int]$s.AntivirusSignatureAge
} catch { $o.errors += 'status' }
try {
    $p = Get-MpPreference
    $o.excl_paths = @($p.ExclusionPath | ForEach-Object { [string]$_ })
    $o.excl_ext = @($p.ExclusionExtension | ForEach-Object { [string]$_ })
    $o.excl_proc = @($p.ExclusionProcess | ForEach-Object { [string]$_ })
    $o.excl_ip = @($p.ExclusionIpAddress | ForEach-Object { [string]$_ })
} catch { $o.errors += 'preference' }
try {
    $o.threats = @(Get-MpThreat | ForEach-Object { [string]$_.ThreatName })
} catch { $o.errors += 'threats' }
$result = [pscustomobject]$o
