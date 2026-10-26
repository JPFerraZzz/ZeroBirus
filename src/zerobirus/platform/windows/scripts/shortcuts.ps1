# Target and arguments of each .lnk in $Params.paths. The shortcut is only read.
$sh = New-Object -ComObject WScript.Shell
$result = foreach ($p in @($Params.paths)) {
    try {
        $l = $sh.CreateShortcut($p)
        [pscustomobject]@{ path = [string]$p; target = [string]$l.TargetPath; arguments = [string]$l.Arguments }
    } catch {
        [pscustomobject]@{ path = [string]$p; target = ''; arguments = '' }
    }
}
