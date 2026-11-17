# AllDrivers: the installed drivers (version and date) and the driver updates that Windows
# Update has pending. Read only: the update search only asks, it installs nothing. A part that
# fails is left out and the report says it could not be read.
function Get-DateText($d) { if ($d) { ([datetime]$d).ToString('yyyy-MM-dd') } else { $null } }
$o = [ordered]@{}
try {
    $classes = @('DISPLAY', 'NET', 'MEDIA', 'BLUETOOTH', 'HDC', 'USB', 'SYSTEM', 'BIOMETRIC')
    $o.installed = @(Get-CimInstance -ClassName Win32_PnPSignedDriver |
        Where-Object { $_.DeviceName -and $_.DriverVersion -and ($classes -contains [string]$_.DeviceClass) } |
        Sort-Object DeviceClass, DeviceName -Unique |
        Select-Object -First 60 |
        ForEach-Object {
            [ordered]@{
                name = [string]$_.DeviceName
                manufacturer = [string]$_.Manufacturer
                version = [string]$_.DriverVersion
                date = (Get-DateText $_.DriverDate)
                class = [string]$_.DeviceClass
            }
        })
} catch { }
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $found = $session.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Driver'")
    $o.pending = @($found.Updates | ForEach-Object { [ordered]@{ title = [string]$_.Title } })
} catch { }
$result = [pscustomobject]$o
