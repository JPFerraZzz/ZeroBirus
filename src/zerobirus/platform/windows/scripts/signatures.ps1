# Authenticode status and signer subject for each path in $Params.paths.
# status is the numeric SignatureStatus (0 Valid, 2 NotSigned, 3 HashMismatch, 4 NotTrusted).
$result = foreach ($p in @($Params.paths)) {
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $p
        $subject = ''
        if ($s.SignerCertificate) { $subject = [string]$s.SignerCertificate.Subject }
        [pscustomobject]@{ path = [string]$p; status = [int]$s.Status; subject = $subject; detail = [string]$s.StatusMessage }
    } catch {
        [pscustomobject]@{ path = [string]$p; status = -1; subject = ''; detail = [string]$_.Exception.Message }
    }
}
