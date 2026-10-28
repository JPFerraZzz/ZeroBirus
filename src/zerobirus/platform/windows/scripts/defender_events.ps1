# Defender scan events (started, completed, stopped, failed) since a given UTC time. Read-only.
# A log that cannot be read is reported in errors, never as "no events".
$since = [datetime]::Parse([string]$Params.since, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
$filter = @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1000, 1001, 1002, 1005; StartTime = $since }
$found = @()
try { $found = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop) }
catch {
    if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') { $errors += ('events: ' + [string]$_.Exception.Message) }
}
$result = foreach ($e in $found) {
    [pscustomobject]@{ id = [int]$e.Id; time = $e.TimeCreated.ToUniversalTime().ToString('o') }
}
