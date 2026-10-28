# Independent read of the state the removal tests care about (does not use the product code).
param([string]$Marker = 'ZeroBirusTest', [string]$Suffix = 'kzqpx')
$ErrorActionPreference = 'SilentlyContinue'
$ns = 'root\subscription'
$dir = Join-Path $env:APPDATA ($Marker + '_' + $Suffix)
$exe = Join-Path $dir 'zbtest.exe'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$svc = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq ($Marker + 'Svc') } | Select-Object -First 1
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$state = [ordered]@{
    run_value = [string](Get-ItemProperty -Path $runKey -Name $Marker).$Marker
    task = [bool](Get-ScheduledTask -TaskName $Marker -TaskPath '\')
    exclusion = [bool]((Get-MpPreference).ExclusionPath -contains $dir)
    exe = [bool](Test-Path $exe)
    process = [bool](Get-Process | Where-Object { $_.Path -eq $exe })
    wmi_filter = [bool](Get-CimInstance -Namespace $ns -ClassName __EventFilter | Where-Object { $_.Name -eq ($Marker + 'Filter') })
    wmi_binding = [bool](Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding | Where-Object { $_.Filter.Name -eq ($Marker + 'Filter') })
    service_start = [string]$svc.StartMode
    service_state = [string]$svc.State
    firewall_rules = @(Get-NetFirewallRule -DisplayName 'ZeroBirus block *').Count
    hosts_lines = @(Get-Content -Path $hosts | Where-Object { $_ -match 'zerobirus-test\.invalid' } | ForEach-Object { [string]$_ })
}
ConvertTo-Json -InputObject $state -Compress
