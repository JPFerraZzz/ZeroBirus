# Extra HARMLESS, MARKED artifacts for the removal integration test (run after
# make_test_artifacts.ps1, on a throwaway machine only): a WMI filter, consumer and binding
# that can never fire, and a service pointing at the marked test program, never started.
param([string]$Marker = 'ZeroBirusTest', [string]$Suffix = 'kzqpx')
$ErrorActionPreference = 'Stop'
$report = [ordered]@{ wmi = $false; service = $false; errors = @() }
$ns = 'root\subscription'
try {
    $query = "SELECT * FROM __InstanceCreationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'zerobirus-never.exe'"
    $f = New-CimInstance -Namespace $ns -ClassName __EventFilter -Property @{ Name = ($Marker + 'Filter'); EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'; Query = $query }
    $cmd = (Join-Path $env:SystemRoot 'System32\cmd.exe') + ' /c exit'
    $c = New-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer -Property @{ Name = ($Marker + 'Consumer'); CommandLineTemplate = $cmd }
    New-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -Property @{ Filter = [Ref]$f; Consumer = [Ref]$c } | Out-Null
    $report.wmi = $true
} catch { $report.errors += ('wmi: ' + $_.Exception.Message) }
try {
    $exe = Join-Path (Join-Path $env:APPDATA ($Marker + '_' + $Suffix)) 'zbtest.exe'
    New-Service -Name ($Marker + 'Svc') -BinaryPathName ('"' + $exe + '"') -StartupType Manual | Out-Null
    $report.service = $true
} catch { $report.errors += ('service: ' + $_.Exception.Message) }
ConvertTo-Json -InputObject $report -Compress
