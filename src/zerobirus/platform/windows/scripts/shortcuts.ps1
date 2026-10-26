# Target and arguments of each .lnk in $Params.paths. The shortcut is only read.
$sh = $null
try { $sh = New-Object -ComObject WScript.Shell } catch { $errors += ('shortcuts: ' + [string]$_.Exception.Message) }
$result = foreach ($p in @($Params.paths)) {
    try {
        $l = $sh.CreateShortcut($p)
        [pscustomobject]@{ path = [string]$p; target = [string]$l.TargetPath; arguments = [string]$l.Arguments }
    } catch {
        $errors += ('shortcut: ' + [string]$_.Exception.Message)
        [pscustomobject]@{ path = [string]$p; target = ''; arguments = '' }
    }
}
