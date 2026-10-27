# Diagnostics for the firewall integration test (prints, changes nothing).
$ErrorActionPreference = 'Continue'
'mpssvc: ' + [string](Get-Service -Name mpssvc -ErrorAction SilentlyContinue).Status
Get-NetFirewallRule -DisplayName 'ZeroBirus*' -ErrorAction SilentlyContinue | Select-Object DisplayName, Name, Enabled, Direction, Action, Group | ConvertTo-Json -Compress
Get-NetFirewallRule -Group 'ZeroBirus' -ErrorAction SilentlyContinue | Select-Object DisplayName | ConvertTo-Json -Compress
$Error | ForEach-Object { [string]$_ }
