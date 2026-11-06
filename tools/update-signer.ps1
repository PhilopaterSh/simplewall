# hardening round 2 (T011) - update feed signer bootstrap
# DEC-05: ECDSA P-256 (CNG-compatible), detached signature = raw 64-byte
# r||s (IEEE P1363) over the EXACT manifest bytes.
#
# Usage:
#   .\tools\update-signer.ps1 -NewKey -KeyPath D:\keys\simplewall-signing.json   # generate keypair
#   .\tools\update-signer.ps1 -ExportPubHex -KeyPath D:\keys\simplewall-signing.json  # print X||Y hex for src\update_key.h
#   .\tools\update-signer.ps1 -Sign -KeyPath D:\keys\simplewall-signing.json -File bin\VERSION  # writes bin\VERSION.sig
#   .\tools\update-signer.ps1 -SelfTest -KeyPath D:\keys\simplewall-signing.json  # RSK-04 gate: must PASS
#
# The PRIVATE key never goes into the repository. Loss = RSK-02 (rotation
# runbook in docs\specs\routine-hardening\verification.md).
[CmdletBinding()]
param(
    [switch]$NewKey,
    [switch]$ExportPubHex,
    [switch]$Sign,
    [switch]$SelfTest,
    [Parameter(Mandatory=$true)][string]$KeyPath,
    [string]$File
)

$ErrorActionPreference = 'Stop'

function Import-Params {
    param([string]$XB64, [string]$YB64, [string]$DB64)
    # PowerShell struct-mutation trap: members of $p.Q (a struct) cannot be
    # mutated in place — build ECPoint locally and assign the whole struct
    $p = New-Object System.Security.Cryptography.ECParameters
    $p.Curve = [System.Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7')
    $q = New-Object System.Security.Cryptography.ECPoint
    $q.X = [Convert]::FromBase64String($XB64)
    $q.Y = [Convert]::FromBase64String($YB64)
    $p.Q = $q
    if ($DB64) { $p.D = [Convert]::FromBase64String($DB64) }
    $ec = [System.Security.Cryptography.ECDsa]::Create()
    $ec.ImportParameters($p)
    return $ec
}

function Load-Key {
    if (-not (Test-Path $KeyPath)) { throw "Key file not found: $KeyPath (generate with -NewKey)" }
    $j = Get-Content $KeyPath -Raw | ConvertFrom-Json
    return Import-Params -XB64 $j.x -YB64 $j.y -DB64 $null
}

function Load-KeyPrivate {
    if (-not (Test-Path $KeyPath)) { throw "Key file not found: $KeyPath (generate with -NewKey)" }
    $j = Get-Content $KeyPath -Raw | ConvertFrom-Json
    return Import-Params -XB64 $j.x -YB64 $j.y -DB64 $j.d
}

if ($NewKey) {
    # Windows PowerShell 5.1 compatible: software key via curve OID
    # (1.2.840.10045.3.1.7 = nistP256) so the private scalar is exportable
    $curve = [System.Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7')
    $ec = [System.Security.Cryptography.ECDsa]::Create($curve)
    $p = $ec.ExportParameters($true)
    $json = [ordered]@{
        curve = 'nistP256'
        d = [Convert]::ToBase64String($p.D)
        x = [Convert]::ToBase64String($p.Q.X)
        y = [Convert]::ToBase64String($p.Q.Y)
        created = (Get-Date -Format 'yyyy-MM-dd')
    } | ConvertTo-Json
    $dir = Split-Path $KeyPath -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [IO.File]::WriteAllText($KeyPath, $json)
    Write-Host "[+] Key pair generated: $KeyPath"
    Write-Host "[!] Keep this file OFF the repository. Loss = RSK-02 rotation."
    exit 0
}

$ec = Load-Key

if ($Sign -or $SelfTest) {
    # signing requires the private scalar
    $ec = Load-KeyPrivate
}

if ($ExportPubHex) {
    $p = $ec.ExportParameters($false)
    $x = ($p.Q.X | ForEach-Object { $_.ToString('x2') }) -join ''
    $y = ($p.Q.Y | ForEach-Object { $_.ToString('x2') }) -join ''
    Write-Host "// paste into src\update_key.h (X||Y, 64 bytes)"
    Write-Host ($x + $y)
    exit 0
}

if ($Sign) {
    if (-not $File) { throw "Pass -File <manifest path>" }
    $bytes = [IO.File]::ReadAllBytes($File)
    $sig = $ec.SignData($bytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    if ($sig.Length -ne 64) { throw "Unexpected signature length $($sig.Length) (expected 64 = raw r||s P1363)" }
    [IO.File]::WriteAllBytes("$File.sig", $sig)
    Write-Host "[+] Signed: $File.sig (64-byte r||s)"
    exit 0
}

if ($SelfTest) {
    # RSK-04 gate: sign->verify round-trip must succeed; tampered must fail
    $msg = [Text.Encoding]::UTF8.GetBytes("simplewall update-signer self-test $(Get-Random)")
    $sig = $ec.SignData($msg, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $ok1 = $ec.VerifyData($msg, $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $tampered = [byte[]]($sig.Clone()); $tampered[0] = $tampered[0] -bxor 0xFF
    $ok2 = $ec.VerifyData($msg, $tampered, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    if ($ok1 -and -not $ok2) { Write-Host "[PASS] SelfTest: round-trip verified, tampered rejected." -ForegroundColor Green; exit 0 }
    Write-Host "[FAIL] SelfTest: ok1=$ok1 ok2=$ok2" -ForegroundColor Red; exit 1
}

Write-Host "Nothing to do - pass -NewKey / -ExportPubHex / -Sign / -SelfTest"
