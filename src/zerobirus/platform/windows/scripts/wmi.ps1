# Permanent WMI event subscriptions: filter, consumer, consumer class and what it runs.
# Consumers and bindings are read separately, so a failure in one is reported without losing
# the other.
$ns = 'root/subscription'
$cons = @{}
try {
    foreach ($c in @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer)) {
        $cons[([string]$c.CimSystemProperties.ClassName + '|' + [string]$c.Name)] = $c
    }
} catch { $errors += ('consumers: ' + [string]$_.Exception.Message) }
$bindings = @()
try { $bindings = @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding) }
catch { $errors += ('bindings: ' + [string]$_.Exception.Message) }
$result = foreach ($b in $bindings) {
    try {
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
    } catch { $errors += ('binding: ' + [string]$_.Exception.Message) }
}
