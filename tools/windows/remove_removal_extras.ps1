# Removes what make_removal_extras.ps1 and the removal tests created, identified by the marker.
param([string]$Marker = 'ZeroBirusTest')
$ErrorActionPreference = 'Continue'
$ns = 'root\subscription'
Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { $_.Filter.Name -eq ($Marker + 'Filter') } | Remove-CimInstance -ErrorAction SilentlyContinue
Get-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq ($Marker + 'Consumer') } | Remove-CimInstance -ErrorAction SilentlyContinue
Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq ($Marker + 'Filter') } | Remove-CimInstance -ErrorAction SilentlyContinue
$sc = Join-Path $env:SystemRoot 'System32\sc.exe'
if (Get-Service -Name ($Marker + 'Svc') -ErrorAction SilentlyContinue) { & $sc delete ($Marker + 'Svc') | Out-Null }
Get-NetFirewallRule -Group 'ZeroBirus' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
if (Test-Path $hosts) {
    $keep = @(Get-Content -Path $hosts | Where-Object { $_ -notmatch 'zerobirus-test\.invalid' })
    Set-Content -Path $hosts -Value $keep
}
Get-ChildItem -Path $env:TEMP -Filter ($Marker + '_tmp*') -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Write-Output 'removed'
