# Authenticode status and signer subject for each path in $Params.paths.
# status is the numeric SignatureStatus (0 Valid, 2 NotSigned, 3 HashMismatch, 4 NotTrusted);
# -1 means this one file could not be checked (detail says why). One bad file never stops the rest.
$result = foreach ($p in @($Params.paths)) {
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $p
        $subject = ''
        if ($s.SignerCertificate) { $subject = [string]$s.SignerCertificate.Subject }
        [pscustomobject]@{ path = [string]$p; status = [int]$s.Status; subject = $subject; detail = [string]$s.StatusMessage }
    } catch {
        $errors += ('signature: ' + [string]$_.Exception.Message)
        [pscustomobject]@{ path = [string]$p; status = -1; subject = ''; detail = [string]$_.Exception.Message }
    }
}
