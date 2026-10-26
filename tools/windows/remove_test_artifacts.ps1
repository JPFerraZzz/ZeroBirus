# Removes everything make_test_artifacts.ps1 created, identified by the marker. Refuses to
# touch anything outside the marked folder under %APPDATA%.
param(
    [string]$Marker = 'ZeroBirusTest',
    [string]$Suffix = 'kzqpx'
)
$ErrorActionPreference = 'Continue'

$dir = Join-Path $env:APPDATA ($Marker + '_' + $Suffix)
$parent = Split-Path -Parent $dir
if ($parent -ne $env:APPDATA -or -not ((Split-Path -Leaf $dir).StartsWith($Marker))) {
    Write-Error 'refusing to remove a folder that is not a marked test folder'
    exit 2
}

Get-Process | Where-Object { $_.Path -and $_.Path.StartsWith($dir) } | Stop-Process -Force
Start-Sleep -Seconds 1
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $Marker -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $Marker -TaskPath '\' -Confirm:$false -ErrorAction SilentlyContinue
try { Remove-MpPreference -ExclusionPath $dir } catch { }
if (Test-Path $dir) { Remove-Item -Path $dir -Recurse -Force }
Write-Output 'removed'
