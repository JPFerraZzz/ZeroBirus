# Creates HARMLESS, MARKED test artifacts for the read-only detection integration test.
# Run only on a throwaway machine (CI runner or a VM). Nothing here is malware: the test
# program just sleeps, and the "miner" command line points to a .invalid domain that never
# resolves. Everything is named with the marker so remove_test_artifacts.ps1 can clean it.
#
# Prints one JSON object describing what was created (optional parts may fail and say so).
param(
    [string]$Marker = 'ZeroBirusTest',
    [string]$Suffix = 'kzqpx'
)
$ErrorActionPreference = 'Stop'

$dir = Join-Path $env:APPDATA ($Marker + '_' + $Suffix)
$exe = Join-Path $dir 'zbtest.exe'
$fakeMinerArgs = '-o stratum+tcp://pool.invalid:3333 --donate-level=1'
$report = [ordered]@{
    marker = $Marker; dir = $dir; exe = $exe; args = $fakeMinerArgs
    exe_created = $false; run_key = $false; task = $false; exclusion = $false; started = $false
    errors = @()
}

New-Item -ItemType Directory -Path $dir -Force | Out-Null

# 1. An unsigned test program that sleeps. Compiled now with the .NET Framework compiler.
$csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$src = Join-Path $dir 'zbtest.cs'
Set-Content -Path $src -Value 'class P { static void Main() { System.Threading.Thread.Sleep(600000); } }' -Encoding ASCII
& $csc /nologo /target:exe ('/out:' + $exe) $src | Out-Null
Remove-Item -Path $src -Force
$report.exe_created = Test-Path $exe

# 2. Persistence: a Run value pointing to the program with a mining-like command line.
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if (-not (Test-Path $runKey)) { New-Item -Path $runKey -Force | Out-Null }
Set-ItemProperty -Path $runKey -Name $Marker -Value ('"' + $exe + '" ' + $fakeMinerArgs)
$report.run_key = $true

# 3. A scheduled task outside \Microsoft, far in the future so it never runs.
try {
    $action = New-ScheduledTaskAction -Execute $exe -Argument $fakeMinerArgs
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskName $Marker -TaskPath '\' -Action $action -Trigger $trigger -Force | Out-Null
    $report.task = $true
} catch { $report.errors += ('task: ' + $_.Exception.Message) }

# 4. A Defender exclusion for the folder (needs administrator and a running Defender).
try {
    Add-MpPreference -ExclusionPath $dir
    $report.exclusion = $true
} catch { $report.errors += ('exclusion: ' + $_.Exception.Message) }

# 5. The test program running, with the mining-like command line.
Start-Process -FilePath $exe -ArgumentList $fakeMinerArgs -WindowStyle Hidden
Start-Sleep -Seconds 2
$report.started = [bool](Get-Process | Where-Object { $_.Path -eq $exe })

$report | ConvertTo-Json -Compress
