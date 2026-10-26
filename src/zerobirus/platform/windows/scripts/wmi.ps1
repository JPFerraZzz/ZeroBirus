# Permanent WMI event subscriptions: filter, consumer, consumer class and what it runs.
$ns = 'root/subscription'
$cons = @{}
foreach ($c in @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer)) {
    $cons[([string]$c.CimSystemProperties.ClassName + '|' + [string]$c.Name)] = $c
}
$result = foreach ($b in @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding)) {
    $cname = [string]$b.Consumer.Name
    $cclass = [string]$b.Consumer.CimSystemProperties.ClassName
    $cmd = ''
    $c = $cons[($cclass + '|' + $cname)]
    if ($c) {
        if ($c.CommandLineTemplate) { $cmd = [string]$c.CommandLineTemplate }
        elseif ($c.ExecutablePath) { $cmd = [string]$c.ExecutablePath }
        elseif ($c.ScriptFileName) { $cmd = [string]$c.ScriptFileName }
        elseif ($c.ScriptText) { $cmd = [string]$c.ScriptText }
    }
    [pscustomobject]@{
        filter = [string]$b.Filter.Name
        consumer = $cname
        consumer_class = $cclass
        command = $cmd
    }
}
