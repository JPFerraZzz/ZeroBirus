# Builds the distributable ZIP: the onedir folder plus LEIA-ME.txt, and its SHA-256 file.
param(
    [Parameter(Mandatory = $true)][string]$ZipName,
    [string]$Dist = 'dist\ZeroBirus',
    [string]$Readme = 'packaging\LEIA-ME.txt'
)
$ErrorActionPreference = 'Stop'
$stage = Join-Path (Get-Location) 'zip-stage'
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Path $stage | Out-Null
Copy-Item -Recurse -Path $Dist -Destination (Join-Path $stage 'ZeroBirus')
Copy-Item -Path $Readme -Destination (Join-Path $stage 'LEIA-ME.txt')
if (Test-Path $ZipName) { Remove-Item -Force $ZipName }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $ZipName
$hash = (Get-FileHash $ZipName -Algorithm SHA256).Hash.ToLower()
"$hash  $ZipName" | Out-File -Encoding ascii SHA256SUMS.txt
Get-Content SHA256SUMS.txt
