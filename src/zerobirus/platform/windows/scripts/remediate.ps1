# Stage 4 actions for an authorised plan. One action per run, chosen by $Params.action from a
# fixed list; every other value is data passed to a cmdlet parameter, never evaluated. A
# failure throws: the caller turns it into a FALHOU with the message.
function Out-Result($ok, $data) { [pscustomobject]@{ ok = [bool]$ok; data = $data } }
function To-Hashtable($o) {
    $h = @{}
    foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = $p.Value }
    $h
}
$ns = 'root\subscription'
$consumerClasses = @('CommandLineEventConsumer', 'ActiveScriptEventConsumer', 'NTEventLogEventConsumer', 'LogFileEventConsumer', 'SMTPEventConsumer')
function Get-Svc($n) {
    Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq $n } | Select-Object -First 1
}
function Get-Excl($kind) {
    $p = Get-MpPreference
    switch ($kind) {
        'path' { @($p.ExclusionPath) }
        'extension' { @($p.ExclusionExtension) }
        'process' { @($p.ExclusionProcess) }
        'ip' { @($p.ExclusionIpAddress) }
        default { throw 'unknown exclusion kind' }
    }
}
function Get-Wmi($filter, $consumer, $class) {
    if ($consumerClasses -notcontains $class) { throw 'consumer class not allowed' }
    $f = Get-CimInstance -Namespace $ns -ClassName __EventFilter | Where-Object { $_.Name -eq $filter } | Select-Object -First 1
    $c = Get-CimInstance -Namespace $ns -ClassName $class | Where-Object { $_.Name -eq $consumer } | Select-Object -First 1
    $b = Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding | Where-Object { $_.Filter.Name -eq $filter -and $_.Consumer.Name -eq $consumer } | Select-Object -First 1
    [pscustomobject]@{ f = $f; c = $c; b = $b }
}
function Get-Props($o) {
    $h = @{}
    foreach ($p in $o.CimInstanceProperties) {
        if ($p.Name -notlike '__*' -and $null -ne $p.Value -and $p.Value -isnot [System.Array]) { $h[$p.Name] = $p.Value }
    }
    $h
}
function Get-FwRules($addr) {
    @(Get-NetFirewallRule -Group 'ZeroBirus' -ErrorAction SilentlyContinue | Where-Object {
        @((Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_).RemoteAddress) -contains $addr
    })
}

$a = [string]$Params.action
switch ($a) {
    'restore_point' {
        $desc = [string]$Params.description
        $why = ''
        try {
            Checkpoint-Computer -Description $desc -RestorePointType 'MODIFY_SETTINGS' -WarningVariable w -WarningAction SilentlyContinue
        } catch { $why = [string]$_.Exception.Message }
        $found = $null
        try { $found = Get-ComputerRestorePoint | Where-Object { $_.Description -eq $desc } | Select-Object -First 1 } catch { }
        if ($found) { $result = Out-Result $true $null }
        else {
            if (-not $why -and $w) { $why = (($w | ForEach-Object { [string]$_ }) -join ' ') }
            $result = Out-Result $false $why
        }
    }
    'task_capture' {
        $xml = Export-ScheduledTask -TaskName ([string]$Params.name) -TaskPath ([string]$Params.folder)
        $result = Out-Result $true ([string]$xml)
    }
    'task_remove' {
        Unregister-ScheduledTask -TaskName ([string]$Params.name) -TaskPath ([string]$Params.folder) -Confirm:$false
        $result = Out-Result $true $null
    }
    'task_exists' {
        $t = @(Get-ScheduledTask -TaskName ([string]$Params.name) -TaskPath ([string]$Params.folder) -ErrorAction SilentlyContinue)
        $result = Out-Result $true ($t.Count -gt 0)
    }
    'task_restore' {
        Register-ScheduledTask -Xml ([string]$Params.xml) -TaskName ([string]$Params.name) -TaskPath ([string]$Params.folder) -Force | Out-Null
        $result = Out-Result $true $null
    }
    'service_state' {
        $s = Get-Svc ([string]$Params.name)
        if (-not $s) { throw 'service not found' }
        $result = Out-Result $true @{ start = [string]$s.StartMode; state = [string]$s.State }
    }
    'service_disable' {
        $n = [string]$Params.name
        Stop-Service -Name $n -Force -ErrorAction SilentlyContinue
        Set-Service -Name $n -StartupType Disabled
        for ($i = 0; $i -lt 40; $i++) {
            $s = Get-Svc $n
            if (-not $s -or $s.State -eq 'Stopped') { break }
            Start-Sleep -Milliseconds 500
        }
        $result = Out-Result $true $null
    }
    'service_restore' {
        $map = @{ 'Auto' = 'Automatic'; 'Manual' = 'Manual'; 'Disabled' = 'Disabled' }
        $mode = $map[[string]$Params.start]
        if (-not $mode) { throw 'start mode cannot be restored automatically' }
        Set-Service -Name ([string]$Params.name) -StartupType $mode
        $result = Out-Result $true $null
    }
    'wmi_capture' {
        $w = Get-Wmi ([string]$Params.filter) ([string]$Params.consumer) ([string]$Params.consumer_class)
        if (-not $w.f -or -not $w.c -or -not $w.b) { throw 'WMI subscription not found' }
        $result = Out-Result $true @{ filter = (Get-Props $w.f); consumer = (Get-Props $w.c) }
    }
    'wmi_remove' {
        $w = Get-Wmi ([string]$Params.filter) ([string]$Params.consumer) ([string]$Params.consumer_class)
        if ($w.b) { Remove-CimInstance -InputObject $w.b }
        if ($w.c) { Remove-CimInstance -InputObject $w.c }
        if ($w.f) { Remove-CimInstance -InputObject $w.f }
        $result = Out-Result $true $null
    }
    'wmi_exists' {
        $w = Get-Wmi ([string]$Params.filter) ([string]$Params.consumer) ([string]$Params.consumer_class)
        $result = Out-Result $true ([bool]($w.b -or $w.c -or $w.f))
    }
    'wmi_restore' {
        if ($consumerClasses -notcontains [string]$Params.consumer_class) { throw 'consumer class not allowed' }
        $fi = New-CimInstance -Namespace $ns -ClassName __EventFilter -Property (To-Hashtable $Params.filter_props)
        $ci = New-CimInstance -Namespace $ns -ClassName ([string]$Params.consumer_class) -Property (To-Hashtable $Params.consumer_props)
        New-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -Property @{ Filter = [Ref]$fi; Consumer = [Ref]$ci } | Out-Null
        $result = Out-Result $true $null
    }
    'defender_remove' {
        $v = [string]$Params.value
        switch ([string]$Params.kind) {
            'path' { Remove-MpPreference -ExclusionPath $v }
            'extension' { Remove-MpPreference -ExclusionExtension $v }
            'process' { Remove-MpPreference -ExclusionProcess $v }
            'ip' { Remove-MpPreference -ExclusionIpAddress $v }
            default { throw 'unknown exclusion kind' }
        }
        $result = Out-Result $true $null
    }
    'defender_add' {
        $v = [string]$Params.value
        switch ([string]$Params.kind) {
            'path' { Add-MpPreference -ExclusionPath $v }
            'extension' { Add-MpPreference -ExclusionExtension $v }
            'process' { Add-MpPreference -ExclusionProcess $v }
            'ip' { Add-MpPreference -ExclusionIpAddress $v }
            default { throw 'unknown exclusion kind' }
        }
        $result = Out-Result $true $null
    }
    'defender_has' {
        $list = Get-Excl ([string]$Params.kind)
        $result = Out-Result $true ($list -contains [string]$Params.value)
    }
    'firewall_add' {
        $addr = [string]$Params.address
        New-NetFirewallRule -DisplayName ('ZeroBirus block ' + $addr) -Group 'ZeroBirus' -Direction Outbound -Action Block -RemoteAddress $addr -Profile Any | Out-Null
        $result = Out-Result $true $null
    }
    'firewall_has' {
        $result = Out-Result $true ((Get-FwRules ([string]$Params.address)).Count -gt 0)
    }
    'firewall_remove' {
        foreach ($r in (Get-FwRules ([string]$Params.address))) { Remove-NetFirewallRule -InputObject $r }
        $result = Out-Result $true $null
    }
    default { throw 'unknown action' }
}
