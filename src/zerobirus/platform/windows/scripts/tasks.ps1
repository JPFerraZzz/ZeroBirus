# Every scheduled task with its actions, trigger types and repeat interval. A task that cannot
# be read is reported in the errors list and skipped; the others are still returned.
$all = @()
try { $all = @(Get-ScheduledTask) } catch { $errors += ('tasks: ' + [string]$_.Exception.Message) }
$result = foreach ($t in $all) {
    try {
        $acts = @($t.Actions | ForEach-Object {
            [pscustomobject]@{ execute = [string]$_.Execute; arguments = [string]$_.Arguments }
        })
        $trigs = @($t.Triggers | ForEach-Object { [string]$_.CimClass.CimClassName })
        $rep = $null
        foreach ($tr in @($t.Triggers)) {
            if ($tr.Repetition -and $tr.Repetition.Interval) { $rep = [string]$tr.Repetition.Interval; break }
        }
        [pscustomobject]@{
            folder = [string]$t.TaskPath
            name = [string]$t.TaskName
            state = [int]$t.State
            actions = $acts
            triggers = $trigs
            repetition = $rep
        }
    } catch { $errors += ('task: ' + [string]$_.Exception.Message) }
}
