# BigDiag: a read-only health reading of the PC. Each part is read on its own, so one failure
# does not hide the others; a part that failed is left out and the report says it could not be
# read. Nothing here changes anything, and no names of people or of the PC are collected.
function Get-DateText($d) { if ($d) { ([datetime]$d).ToString('yyyy-MM-dd') } else { $null } }
$o = [ordered]@{}
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $hot = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    $o.os = [ordered]@{
        caption = [string]$os.Caption
        build = [string]$os.BuildNumber
        uptime_days = [int]((Get-Date) - $os.LastBootUpTime).TotalDays
        last_update = (Get-DateText $hot.InstalledOn)
    }
} catch { }
try {
    $o.cpu = @(Get-CimInstance -ClassName Win32_Processor | ForEach-Object {
        [ordered]@{ name = [string]$_.Name; cores = [int]$_.NumberOfCores; threads = [int]$_.NumberOfLogicalProcessors }
    })
} catch { }
try {
    $zones = @(Get-CimInstance -Namespace 'root/wmi' -ClassName MSAcpi_ThermalZoneTemperature)
    if ($zones.Count -gt 0) {
        $o.cpu_temp_c = [int](($zones | Measure-Object -Property CurrentTemperature -Maximum).Maximum / 10 - 273.15)
    }
} catch { }
try {
    $o.ram_modules = @(Get-CimInstance -ClassName Win32_PhysicalMemory | ForEach-Object {
        [ordered]@{ speed_mhz = [int]$_.Speed; size = [int64]$_.Capacity }
    })
} catch { }
try {
    $o.disks = @(Get-PhysicalDisk | ForEach-Object {
        $d = [ordered]@{
            name = [string]$_.FriendlyName
            media = if ([string]$_.BusType -eq 'NVMe') { 'NVMe' } else { [string]$_.MediaType }
            size = [int64]$_.Size
            health = [string]$_.HealthStatus
        }
        try {
            $r = $_ | Get-StorageReliabilityCounter
            if ($r) {
                if ($null -ne $r.Wear) { $d.wear_percent = [int]$r.Wear }
                if ($null -ne $r.Temperature) { $d.temperature_c = [int]$r.Temperature }
                if ($null -ne $r.PowerOnHours) { $d.power_on_hours = [int64]$r.PowerOnHours }
                if ($null -ne $r.ReadErrorsTotal) { $d.read_errors = [int64]$r.ReadErrorsTotal }
                if ($null -ne $r.WriteErrorsTotal) { $d.write_errors = [int64]$r.WriteErrorsTotal }
            }
        } catch { }
        $d
    })
} catch { }
try {
    $o.volumes = @(Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' } | ForEach-Object {
        [ordered]@{ letter = [string]$_.DriveLetter; size = [int64]$_.Size; free = [int64]$_.SizeRemaining }
    })
} catch { }
try {
    $o.gpus = @(Get-CimInstance -ClassName Win32_VideoController | ForEach-Object {
        [ordered]@{ name = [string]$_.Name; driver_version = [string]$_.DriverVersion; driver_date = (Get-DateText $_.DriverDate) }
    })
} catch { }
try {
    $m = [ordered]@{ version = $null; last_run = $null; outcome = $null }
    $reg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\RemovalTools\MRT' -ErrorAction SilentlyContinue
    if ($reg) { $m.version = [string]$reg.Version }
    $log = Join-Path $env:SystemRoot 'debug\mrt.log'
    if (Test-Path -LiteralPath $log) {
        $m.last_run = (Get-DateText (Get-Item -LiteralPath $log).LastWriteTime)
        $tail = @(Get-Content -LiteralPath $log -Tail 300 -ErrorAction Stop)
        if ($tail -match 'No infection found') { $m.outcome = 'clean' }
        elseif ($tail -match 'Threat|Infection') { $m.outcome = 'threats' }
    }
    $o.mrt = $m
} catch { }
try {
    $since = (Get-Date).AddDays(-30)
    function Get-Count($filter) { @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue).Count }
    $o.failures = [ordered]@{
        unexpected_shutdowns = (Get-Count @{ LogName = 'System'; Id = 41; StartTime = $since })
        bugchecks = (Get-Count @{ LogName = 'System'; Id = 1001; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; StartTime = $since })
        app_crashes = (Get-Count @{ LogName = 'Application'; Id = 1000; StartTime = $since })
        disk_errors = (Get-Count @{ LogName = 'System'; ProviderName = 'disk'; Level = 2; StartTime = $since })
    }
} catch { }
$result = [pscustomobject]$o
